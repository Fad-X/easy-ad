//! Pre-Windows-2000 computer accounts: weak default machine passwords.

use super::{AttackContext, require_nxc};
use crate::findings::{CheckStatus, Finding, ScanResults, Severity};
use crate::scanner::ldap::{LdapClient, COMPUTER_ATTRS, pre2k_filter};
use anyhow::Result;

/// Find pre-2k computer accounts via LDAP and attempt TGT acquisition with
/// the default machine password (`<machine-name-lowercase without $>`) via nxc.
pub async fn run(ctx: &AttackContext<'_>, results: &ScanResults) -> Result<()> {
    let entries = ctx
        .ldap
        .search(&ctx.ldap_base_dn(), pre2k_filter(), COMPUTER_ATTRS)
        .await?;

    if entries.is_empty() {
        results.push(Finding::new(
            ctx.dc,
            "kerberos",
            "pre2k",
            CheckStatus::NotVulnerable,
            Severity::Info,
            serde_json::json!({ "message": "no pre-Windows-2000 computer accounts found" }),
        ));
        return Ok(());
    }

    for e in &entries {
        let sam = LdapClient::attr(e, "sAMAccountName").unwrap_or("?");
        results.push(Finding::new(
            ctx.dc,
            "kerberos",
            "pre2k",
            CheckStatus::Vulnerable,
            Severity::Medium,
            serde_json::json!({
                "account": sam,
                "note": "machine password defaults to lowercase account name without '$'",
            }),
        ));
    }

    let nxc = match require_nxc(ctx.nxc) {
        Ok(n) => n,
        Err(err) => {
            results.push(Finding::new(
                ctx.dc,
                "kerberos",
                "pre2k",
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
    args.extend(["-M", "pre2k"]);
    match nxc.run(&args).await {
        Ok((stdout, stderr, success)) => {
            let status = if success { CheckStatus::Success } else { CheckStatus::Error };
            results.push(Finding::new(
                ctx.dc,
                "kerberos",
                "pre2k",
                status,
                Severity::Info,
                serde_json::json!({
                    "message": "nxc pre2k module finished",
                    "stdout": stdout.trim(),
                    "stderr": stderr.trim(),
                }),
            ));
        }
        Err(e) => {
            results.push(Finding::new(
                ctx.dc,
                "kerberos",
                "pre2k",
                CheckStatus::Error,
                Severity::Info,
                serde_json::json!({ "message": e.to_string() }),
            ));
        }
    }
    Ok(())
}
