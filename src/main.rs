//! easy-ad: fast, automated Active Directory enumeration and attack-path scanner.

use anyhow::Result;
use chrono::Utc;
use easy_ad::attack_paths::{self, AttackContext};
use easy_ad::auth::{CredentialRecord, Credentials, Secret};
use easy_ad::cli::Cli;
use easy_ad::discovery::{self, Host};
use easy_ad::findings::{CheckStatus, Finding, ScanResults};
use easy_ad::report::{HostRecord, ReportData};
use easy_ad::scanner::{ldap, smb, ScanContext};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    use clap::{CommandFactory, FromArgMatches};
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches)
        .map_err(|e| anyhow::anyhow!("argument parsing failed: {}", e))?;
    if let Some(cfg_path) = cli.config.clone() {
        easy_ad::cli::apply_config(&mut cli, &matches, &cfg_path)?;
        println!("[*] Loaded config file {}", cfg_path.display());
    }
    if cli.target.is_empty() {
        anyhow::bail!("--target is required (or set target in the config file)");
    }
    if cli.domain.is_empty() {
        anyhow::bail!("--domain is required (or set domain in the config file)");
    }
    let checks = cli.checks();

    // ---- output layout: <output>/<timestamp>/ ----
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let out_dir = PathBuf::from(&cli.output).join(stamp);
    std::fs::create_dir_all(&out_dir)?;

    // ---- logging: console + audit file ----
    let log_path = out_dir.join("easy-ad.log");
    let log_file = std::fs::File::create(&log_path)?;
    let filter = if cli.verbose { "easy_ad=debug,info" } else { "info" };
    let _guard = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::sync::Mutex::new(log_file))
        .with_ansi(false)
        .init();

    tracing::info!(version = env!("CARGO_PKG_VERSION"), target = %cli.target, domain = %cli.domain, "easy-ad starting");

    // ---- credentials ----
    let creds: Option<Credentials> = match (&cli.username, &cli.password, &cli.hash) {
        (Some(u), Some(p), _) => Some(Credentials::with_password(u.clone(), p.clone(), cli.kerberos)),
        (Some(u), None, Some(h)) => Some(Credentials::hash(u.clone(), h.clone())),
        (Some(u), None, None) => {
            eprintln!("[!] username given without --password or --hash; proceeding unauthenticated");
            Some(Credentials::with_password(u.clone(), String::new(), cli.kerberos))
        }
        (None, _, _) => {
            eprintln!("[!] no credentials supplied; anonymous checks only (limited)");
            None
        }
    };

    // ---- target expansion + host probing ----
    println!("[*] Expanding targets: {}", cli.target);
    let ips = discovery::expand_targets(&cli.target).await?;
    println!("[*] Probing {} host(s) ({} threads, {}s timeout)", ips.len(), cli.threads, cli.timeout);
    let hosts = discovery::probe_hosts(ips, cli.threads, cli.timeout).await;
    let up: Vec<&Host> = hosts.iter().filter(|h| h.is_up()).collect();
    println!("[*] {} host(s) up", up.len());
    for h in &up {
        println!("    {:<16} ports: {}", h.ip.to_string(), ports_str(&h.open_ports));
    }

    // ---- DC discovery ----
    let dc = match &cli.dc {
        Some(dc) => dc.clone(),
        None => {
            println!("[*] Discovering Domain Controller via DNS SRV for {} ...", cli.domain);
            match discovery::discover_dc(&cli.domain).await {
                Ok(dc) => {
                    println!("[+] DC: {}", dc);
                    dc
                }
                Err(e) => {
                    // Fall back to the first host with LDAP/LDAPS open.
                    let fallback = up
                        .iter()
                        .find(|h| h.open_ports.contains(&389) || h.open_ports.contains(&636))
                        .map(|h| h.ip.to_string());
                    match fallback {
                        Some(dc) => {
                            eprintln!("[!] SRV lookup failed ({}); using {} (open LDAP port)", e, dc);
                            dc
                        }
                        None => anyhow::bail!("cannot determine DC: {} (pass --dc)", e),
                    }
                }
            }
        }
    };

    let results = Arc::new(ScanResults::new());
    let timeout = Duration::from_secs(cli.timeout);
    let ctx = ScanContext::new(creds.clone(), cli.domain.clone(), dc.clone(), timeout);
    let need_nxc = checks.kerberoast
        || checks.asreproast
        || checks.pre2k
        || checks.coerce
        || checks.gmsa
        || checks.shares
        || matches!(creds.as_ref().map(|c| &c.secret), Some(Secret::NtlmHash(_)))
        // tiberius Windows auth is Windows-only; nxc covers MSSQL elsewhere.
        || (cfg!(not(windows)) && checks.mssql);
    let nxc = if need_nxc {
        easy_ad::nxc::ensure_nxc(!cli.no_nxc_install).await?
    } else {
        None
    };

    // ---- Kerberos preflight ----
    // `-k` only changes behaviour when a KDC is reachable; the native
    // protocol clients silently negotiate NTLM otherwise. Say so loudly
    // instead of recording a misleading "kerberos: true" credential.
    if creds.as_ref().map(|c| c.kerberos).unwrap_or(false) {
        let kdc_addr = format!("{}:88", dc);
        let reachable = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&kdc_addr))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
        if !reachable {
            eprintln!(
                "[!] Kerberos requested (-k) but KDC {} is unreachable; native checks will fall back to NTLM",
                kdc_addr
            );
            results.push(Finding::new(
                &dc,
                "kerberos",
                "kdc",
                CheckStatus::Error,
                easy_ad::findings::Severity::Info,
                serde_json::json!({
                    "message": format!("Kerberos requested but KDC {} unreachable; native checks fell back to NTLM", kdc_addr),
                }),
            ));
        }
    }

    // ---- LDAP collection (once, against the DC) ----
    let ldap_client = match ldap::LdapClient::connect(&dc, timeout).await {
        Ok(mut client) => {
            match client.bind(creds.as_ref(), &cli.domain).await {
                Ok(()) => {
                    println!("[+] LDAP bind OK on {}", dc);
                    results.push(Finding::info(&dc, "ldap", "bind", "LDAP bind successful"));
                    Some(client)
                }
                Err(e) => {
                    eprintln!("[!] LDAP bind failed on {}: {}", dc, e);
                    results.push(Finding::new(
                        &dc,
                        "ldap",
                        "bind",
                        CheckStatus::AccessDenied,
                        easy_ad::findings::Severity::Info,
                        serde_json::json!({ "message": e.to_string() }),
                    ));
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("[!] LDAP connect failed on {}: {}", dc, e);
            None
        }
    };

    let ldap_data = if let Some(client) = ldap_client.as_ref() {
        match ldap::LdapData::collect(client, &ctx.base_dn).await {
            Ok(data) => {
                println!(
                    "[+] LDAP: {} users, {} groups, {} computers, {} OUs, {} GPOs, {} trusts",
                    data.users.len(),
                    data.groups.len(),
                    data.computers.len(),
                    data.ous.len(),
                    data.gpos.len(),
                    data.trusts.len()
                );
                // Password policy finding.
                if let Some(dom) = data.domain.first() {
                    let get = |k: &str| ldap::LdapClient::attr(dom, k).unwrap_or("").to_string();
                    results.push(Finding::new(
                        &dc,
                        "ldap",
                        "password_policy",
                        CheckStatus::Success,
                        easy_ad::findings::Severity::Info,
                        serde_json::json!({
                            "min_password_length": get("minPwdLength"),
                            "password_history": get("pwdHistoryLength"),
                            "max_password_age": get("maxPwdAge"),
                            "lockout_threshold": get("lockOutBadCount"),
                            "min_password_age": get("minPwdAge"),
                        }),
                    ));
                }
                Some(data)
            }
            Err(e) => {
                eprintln!("[!] LDAP collection failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Parsed accounts feed attack-path checks and reports.
    let accounts: Vec<easy_ad::discovery::parser::ParsedAccount> = ldap_data
        .as_ref()
        .map(|d| {
            easy_ad::discovery::parser::parse_accounts(
                &d.users.iter().map(ldap::entry_to_raw_account).collect::<Vec<_>>(),
            )
        })
        .unwrap_or_default();
    if !accounts.is_empty() {
        println!("[+] Parsed {} unique accounts ({} enabled)", accounts.len(), accounts.iter().filter(|a| a.enabled).count());
    }

    // ---- per-host protocol checks ----
    let sem = Arc::new(Semaphore::new(cli.threads.max(1)));
    let mut tasks = Vec::new();
    let target_hosts: Vec<String> = up.iter().map(|h| h.ip.to_string()).collect();

    for host in target_hosts.clone() {
        let ctx = ctx.clone();
        let results = results.clone();
        let sem = sem.clone();
        let creds = creds.clone();
        let nxc = nxc.clone();
        let checks = checks;
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            // SMB access check validates credentials per host.
            if let Some(c) = &creds {
                let is_hash = matches!(c.secret, Secret::NtlmHash(_));
                let f = if is_hash {
                    match &nxc {
                        // NTLM-hash auth is delegated to nxc (native path is
                        // password-only).
                        Some(n) => smb::check_access_nxc(n, &host, c).await,
                        None => smb::check_access(&host, c, &ctx.domain, cli_timeout(ctx.timeout)).await,
                    }
                } else {
                    smb::check_access(&host, c, &ctx.domain, cli_timeout(ctx.timeout)).await
                };
                let is_success = f.status == CheckStatus::Success;
                results.push(f);
                if is_success {
                    results.push(Finding::new(
                        &host,
                        "credentials",
                        "validated",
                        CheckStatus::Success,
                        easy_ad::findings::Severity::Info,
                        serde_json::json!({
                            "username": c.username,
                            "protocol": "smb",
                            "note": "credentials validated on this host",
                        }),
                    ));
                }
                // Full share enumeration via nxc.
                if checks.shares {
                    if let Some(nxc) = &nxc {
                        match smb::enumerate_shares(nxc, &host, c).await {
                            Ok(entries) => {
                                for f in smb::shares_to_findings(&entries) {
                                    results.push(f);
                                }
                                SHARE_ENTRIES.lock().unwrap().extend(entries);
                            }
                            Err(e) => tracing::warn!("share enumeration failed on {}: {}", host, e),
                        }
                    }
                }
            }
            if checks.winrm {
                if let Some(c) = &creds {
                    let f = easy_ad::scanner::winrm::check_access(&host, c, &ctx.domain, cli_timeout(ctx.timeout)).await;
                    results.push(f);
                }
            }
            if checks.rdp {
                let f = easy_ad::scanner::rdp::check(&host, cli_timeout(ctx.timeout)).await;
                results.push(f);
            }
            if checks.mssql {
                if let Some(c) = &creds {
                    // tiberius Windows auth is Windows-only; on other platforms
                    // (and for hash auth) delegate to nxc.
                    #[cfg(windows)]
                    let f = easy_ad::scanner::mssql::check(&host, c, &ctx.domain, cli_timeout(ctx.timeout)).await;
                    #[cfg(not(windows))]
                    let f = match &nxc {
                        Some(n) => easy_ad::scanner::mssql::check_nxc(n, &host, c).await,
                        None => easy_ad::scanner::mssql::check(&host, c, &ctx.domain, cli_timeout(ctx.timeout)).await,
                    };
                    results.push(f);
                }
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }

    // ---- attack-path checks (against the DC) ----
    if let (Some(client), Some(c)) = (ldap_client.as_ref(), creds.as_ref()) {
        let actx = AttackContext {
            creds: c,
            domain: &cli.domain,
            dc: &dc,
            ldap: client,
            nxc: nxc.as_ref(),
            out_dir: &out_dir,
        };
        if checks.kerberoast {
            println!("[*] Kerberoasting ...");
            if let Err(e) = attack_paths::kerberoast::run(&actx, &results).await {
                eprintln!("[!] kerberoast: {}", e);
            }
        }
        if checks.asreproast {
            println!("[*] AS-REP Roasting ...");
            if let Err(e) = attack_paths::asreproast::run(&actx, &results).await {
                eprintln!("[!] asreproast: {}", e);
            }
        }
        if checks.pre2k {
            println!("[*] Pre2k check ...");
            if let Err(e) = attack_paths::pre2k::run(&actx, &results).await {
                eprintln!("[!] pre2k: {}", e);
            }
        }
        if checks.coerce {
            println!("[*] Coercion scan (coerce_plus) ...");
            let coerce_hosts: Vec<String> = target_hosts.clone();
            if let Err(e) = attack_paths::coercion::run(&actx, &coerce_hosts, None, &results).await {
                eprintln!("[!] coerce: {}", e);
            }
        }
        if checks.gmsa {
            println!("[*] gMSA check ...");
            if let Err(e) = attack_paths::gmsa::run(&actx, &results).await {
                eprintln!("[!] gmsa: {}", e);
            }
        }
    } else if checks.kerberoast || checks.asreproast || checks.pre2k || checks.coerce || checks.gmsa {
        eprintln!("[!] attack-path checks require a bound LDAP connection; skipped");
    }

    // ---- BloodHound collection ----
    let mut bh_zip: Option<PathBuf> = None;
    if cli.bloodhound {
        if let Some(data) = ldap_data.as_ref() {
            let bh_dir = cli
                .bh_output
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_else(|| out_dir.join("bloodhound"));
            println!("[*] BloodHound CE collection -> {}", bh_dir.display());
            match easy_ad::bloodhound::write_bloodhound_json(data, &cli.domain, &bh_dir) {
                Ok(files) => {
                    println!("[+] wrote {} BloodHound JSON files", files.len());
                    let zip_path = bh_dir.join(format!("{}_bloodhound.zip", cli.domain.replace('.', "-")));
                    match easy_ad::bloodhound::ingest::package(&bh_dir, &zip_path) {
                        Ok(p) => {
                            println!("[+] BloodHound archive: {}", p.display());
                            bh_zip = Some(p);
                        }
                        Err(e) => eprintln!("[!] bloodhound zip failed: {}", e),
                    }
                }
                Err(e) => eprintln!("[!] bloodhound collection failed: {}", e),
            }
        } else {
            eprintln!("[!] --bloodhound requires LDAP data; skipped");
        }
    }

    // ---- reports ----
    let findings = results.all();
    let shares = SHARE_ENTRIES.lock().unwrap().clone();
    let credentials_records: Vec<CredentialRecord> = findings
        .iter()
        .filter(|f| f.check == "validated")
        .filter_map(|_f| creds.as_ref().map(CredentialRecord::from))
        .collect();

    let report = ReportData {
        domain: cli.domain.clone(),
        dc: dc.clone(),
        started: Utc::now(),
        hosts: hosts
            .iter()
            .map(|h| HostRecord { ip: h.ip.to_string(), open_ports: h.open_ports.clone() })
            .collect(),
        accounts,
        shares,
        findings,
        credentials: credentials_records,
        bloodhound_zip: bh_zip,
    };

    println!("[*] Writing reports to {}", out_dir.display());
    let written = easy_ad::report::write_reports(&report, &out_dir, cli.want_json(), cli.want_pdf(), cli.include_hashes)?;
    for w in &written {
        println!("[+] {}", w.display());
    }
    println!("[*] Audit log: {}", log_path.display());
    println!("[*] Done. {} finding(s).", report.findings.len());

    Ok(())
}

fn cli_timeout(d: Duration) -> u64 {
    d.as_secs()
}

fn ports_str(ports: &[u16]) -> String {
    ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
}

/// Per-run share entries collected by parallel tasks.
static SHARE_ENTRIES: std::sync::Mutex<Vec<easy_ad::discovery::parser::ShareEntry>> =
    std::sync::Mutex::new(Vec::new());
