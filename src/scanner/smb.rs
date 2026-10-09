//! SMB enumeration: access validation and share permission collection.
//!
//! Native: authenticated tree-connect against `\\host\IPC$` using the pure-Rust
//! `smb` crate (SMB2/3). Full share + ACL enumeration is delegated to nxc
//! (`--shares`), which parses into structured [`ShareEntry`] records.

use crate::auth::{Credentials, Secret};
use crate::discovery::parser::{ShareEntry, parse_nxc_shares};
use crate::findings::{CheckStatus, Finding, Severity};
use crate::nxc::NxcHandle;
use anyhow::Result;
use smb::{Client, ClientConfig, UncPath};
use std::str::FromStr;
use std::time::Duration;
use tokio::time::timeout;

/// Try to authenticate to SMB on `host` by tree-connecting IPC$.
///
/// Returns a finding; `Ok(Some(Finding))` with status Success means credentials
/// are valid for SMB on this host.
pub async fn check_access(
    host: &str,
    creds: &Credentials,
    domain: &str,
    timeout_secs: u64,
) -> Finding {
    let unc = format!(r"\\{}\IPC$", host);
    let result = timeout(Duration::from_secs(timeout_secs), async {
        let client = Client::new(ClientConfig::default());
        let path = UncPath::from_str(&unc).map_err(|e| anyhow::anyhow!("bad UNC path: {}", e))?;
        let password = match &creds.secret {
            Secret::Password(p) => p.clone(),
            Secret::NtlmHash(_) => {
                return Err(anyhow::anyhow!(
                    "native SMB hash auth not implemented; use nxc fallback (-H)"
                ))
            }
        };
        client
            .share_connect(&path, &creds.qualified(domain), password)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
    })
    .await;

    match result {
        Ok(Ok(())) => Finding::new(
            host,
            "smb",
            "access",
            CheckStatus::Success,
            Severity::Info,
            serde_json::json!({ "message": "SMB authentication successful (IPC$ tree connect)" }),
        ),
        Ok(Err(e)) => {
            let msg = e.to_string().to_lowercase();
            let status = if msg.contains("logon") || msg.contains("access denied") || msg.contains("status_access_denied") || msg.contains("unauthorized") {
                CheckStatus::AccessDenied
            } else {
                CheckStatus::Error
            };
            Finding::new(host, "smb", "access", status, Severity::Info, serde_json::json!({ "message": e.to_string() }))
        }
        Err(_) => Finding::new(host, "smb", "access", CheckStatus::Unreachable, Severity::Info, serde_json::json!({ "message": "timeout" })),
    }
}

/// Check SMB access via nxc (used for NTLM-hash auth, which the native
/// `smb` crate path cannot do). Secrets are never stored in the finding.
pub async fn check_access_nxc(nxc: &NxcHandle, host: &str, creds: &Credentials) -> Finding {
    let mut args: Vec<&str> = vec!["smb", host];
    let secret = if let Some(p) = creds.password() {
        vec!["-u".to_string(), creds.username.clone(), "-p".to_string(), p.to_string()]
    } else {
        vec![
            "-u".to_string(),
            creds.username.clone(),
            "-H".to_string(),
            creds.secret.nt_part().unwrap_or_default(),
        ]
    };
    let secret_refs: Vec<&str> = secret.iter().map(String::as_str).collect();
    args.extend(secret_refs);

    match nxc.run(&args).await {
        Ok((stdout, _stderr, _)) => {
            // nxc prints lines like: [+] DOMAIN\user:<secret>  /  [-] ...:<secret>
            // Never persist these lines - they contain the password/hash.
            let user_up = creds.username.to_uppercase();
            let ok_line = stdout.lines().any(|l| l.contains("[+]") && l.to_uppercase().contains(&user_up));
            let denied_line = stdout.lines().any(|l| l.contains("[-]"));
            if ok_line {
                Finding::new(
                    host,
                    "smb",
                    "access",
                    CheckStatus::Success,
                    Severity::Info,
                    serde_json::json!({ "message": "SMB authentication successful (nxc NTLM hash auth)" }),
                )
            } else if denied_line {
                Finding::new(
                    host,
                    "smb",
                    "access",
                    CheckStatus::AccessDenied,
                    Severity::Info,
                    serde_json::json!({ "message": "SMB authentication denied (nxc)" }),
                )
            } else {
                Finding::new(
                    host,
                    "smb",
                    "access",
                    CheckStatus::Error,
                    Severity::Info,
                    serde_json::json!({ "message": "nxc smb check returned no clear result" }),
                )
            }
        }
        Err(e) => Finding::new(
            host,
            "smb",
            "access",
            CheckStatus::Error,
            Severity::Info,
            serde_json::json!({ "message": format!("nxc invocation failed: {}", e) }),
        ),
    }
}

/// Enumerate shares + permissions via nxc `--shares` (password or hash auth).
pub async fn enumerate_shares(
    nxc: &NxcHandle,
    host: &str,
    creds: &Credentials,
) -> Result<Vec<ShareEntry>> {
    let mut args: Vec<&str> = vec!["smb", host];
    let u = creds.username.clone();
    let secret;
    let s_flag;
    if let Some(p) = creds.password() {
        secret = p.to_string();
        s_flag = "-p";
    } else {
        secret = creds
            .secret
            .nt_part()
            .unwrap_or_default();
        s_flag = "-H";
    }
    args.extend(["-u", u.as_str(), s_flag, secret.as_str(), "--shares"]);
    let (stdout, stderr, success) = nxc.run(&args).await?;
    if !success && stdout.trim().is_empty() {
        anyhow::bail!("nxc smb --shares failed on {}: {}", host, stderr.trim());
    }
    Ok(parse_nxc_shares(host, &stdout))
}

/// Render share entries as findings (one per readable/writable share).
pub fn shares_to_findings(entries: &[ShareEntry]) -> Vec<Finding> {
    entries
        .iter()
        .filter(|e| e.perms.read || e.perms.write)
        .map(|e| {
            let severity = if e.perms.write { Severity::Medium } else { Severity::Low };
            Finding::new(
                &e.host,
                "smb",
                "shares",
                CheckStatus::Success,
                severity,
                serde_json::json!({
                    "share": e.share,
                    "remark": e.remark,
                    "read": e.perms.read,
                    "write": e.perms.write,
                    "execute": e.perms.execute,
                }),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_findings_flag_writable_as_medium() {
        let entries = vec![ShareEntry {
            host: "10.0.0.5".into(),
            share: "secrets".into(),
            remark: String::new(),
            perms: crate::discovery::parser::SharePerms { read: true, write: true, execute: false },
        }];
        let f = shares_to_findings(&entries);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }
}
