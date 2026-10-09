//! WinRM (WS-Management) access check and command execution via `winrm-rs`.

use crate::auth::{Credentials, Secret};
use crate::findings::{CheckStatus, Finding, Severity};
use anyhow::Result;
use std::time::Duration;
use tokio::time::timeout;
use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

/// Attempt to open a WinRM shell on `host` and run a harmless command.
pub async fn check_access(host: &str, creds: &Credentials, domain: &str, timeout_secs: u64) -> Finding {
    let result = timeout(Duration::from_secs(timeout_secs), async {
        let password = match &creds.secret {
            Secret::Password(p) => p.clone(),
            Secret::NtlmHash(_) => {
                return Err(anyhow::anyhow!(
                    "winrm-rs does not accept raw NTLM hashes; use nxc fallback (-H)"
                ))
            }
        };
        let wcreds = WinrmCredentials::new(creds.krb_user(), password, domain);
        let client = WinrmClient::new(WinrmConfig::default(), wcreds)?;
        client
            .run_command(host, "whoami", &[])
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
    })
    .await;

    match result {
        Ok(Ok(out)) => Finding::new(
            host,
            "winrm",
            "access",
            CheckStatus::Success,
            Severity::Info,
            serde_json::json!({
                "message": "WinRM shell opened and command executed",
                "stdout": String::from_utf8_lossy(&out.stdout).trim(),
            }),
        ),
        Ok(Err(e)) => {
            let msg = e.to_string().to_lowercase();
            let status = if msg.contains("401") || msg.contains("unauthorized") || msg.contains("denied") || msg.contains("auth") {
                CheckStatus::AccessDenied
            } else {
                CheckStatus::Error
            };
            Finding::new(host, "winrm", "access", status, Severity::Info, serde_json::json!({ "message": e.to_string() }))
        }
        Err(_) => Finding::new(host, "winrm", "access", CheckStatus::Unreachable, Severity::Info, serde_json::json!({ "message": "timeout" })),
    }
}

/// Execute an arbitrary command over WinRM (used for extended checks).
pub async fn exec(
    host: &str,
    creds: &Credentials,
    domain: &str,
    command: &str,
    timeout_secs: u64,
) -> Result<(String, String)> {
    let password = match &creds.secret {
        Secret::Password(p) => p.clone(),
        Secret::NtlmHash(_) => anyhow::bail!("WinRM exec requires a password"),
    };
    timeout(Duration::from_secs(timeout_secs), async {
        let wcreds = WinrmCredentials::new(creds.krb_user(), password, domain);
        let client = WinrmClient::new(WinrmConfig::default(), wcreds)?;
        let out = client.run_command(host, command, &[]).await?;
        Ok((
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        ))
    })
    .await
    .map_err(|_| anyhow::anyhow!("WinRM exec timed out"))?
}
