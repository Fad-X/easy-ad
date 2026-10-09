//! MSSQL access check via the `tiberius` TDS driver.

use crate::auth::{Credentials, Secret};
use crate::findings::{CheckStatus, Finding, Severity};
use anyhow::{Context, Result};
use futures::TryStreamExt;
use std::time::Duration;
use tiberius::{AuthMethod, Client, Config, QueryItem};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

type TdsClient = Client<Compat<TcpStream>>;

/// Build a TDS client config for the given credentials.
///
/// Uses Windows (NTLM) authentication via `DOMAIN\user` - matching nxc's
/// default behavior - since most lab/enterprise instances accept Windows auth.
pub fn build_config(host: &str, port: u16, creds: &Credentials, domain: &str) -> Result<Config> {
    let mut config = Config::new();
    config.host(host);
    config.port(port);
    match &creds.secret {
        Secret::Password(p) => {
            #[cfg(windows)]
            config.authentication(AuthMethod::windows(creds.qualified(domain), p));
            // tiberius only implements Windows (SSPI) auth on Windows hosts;
            // on other platforms the caller must use the nxc fallback.
            #[cfg(not(windows))]
            anyhow::bail!("native MSSQL Windows auth is Windows-only; use nxc fallback");
        }
        Secret::NtlmHash(_) => {
            // tiberius Windows auth is password-based; a raw NT hash is not a
            // supported client credential. Defer to nxc mssql for hash auth.
            anyhow::bail!("native MSSQL does not accept raw NTLM hashes; use nxc fallback (-H)");
        }
    }
    config.trust_cert(); // pentest tooling: we do not require valid TLS
    Ok(config)
}

/// Connect + authenticate, returning the client.
pub async fn connect(config: Config, timeout_secs: u64) -> Result<TdsClient> {
    let addr = config.get_addr();
    let tcp = timeout(Duration::from_secs(timeout_secs), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("MSSQL connect timed out"))?
        .context("MSSQL TCP connect failed")?;
    tcp.set_nodelay(true).context("set_nodelay failed")?;
    let client = Client::connect(config, tcp.compat_write())
        .await
        .context("MSSQL TDS auth failed")?;
    Ok(client)
}

/// Check MSSQL access on `host:1433` and fingerprint the instance.
pub async fn check(host: &str, creds: &Credentials, domain: &str, timeout_secs: u64) -> Finding {
    let result = timeout(Duration::from_secs(timeout_secs), async {
        let config = build_config(host, 1433, creds, domain)?;
        let mut client = connect(config, timeout_secs).await?;
        let mut stream = client
            .query("SELECT @@VERSION, SYSTEM_USER", &[])
            .await
            .context("MSSQL query failed")?;
        let mut version = String::new();
        let mut system_user = String::new();
        while let Some(item) = stream.try_next().await.context("TDS row stream error")? {
            if let QueryItem::Row(row) = item {
                if let Ok(Some(v)) = row.try_get::<&str, _>(0) {
                    version = v.chars().take(120).collect();
                }
                if let Ok(Some(u)) = row.try_get::<&str, _>(1) {
                    system_user = u.to_string();
                }
            }
        }
        Ok::<_, anyhow::Error>(serde_json::json!({
            "message": "MSSQL authentication successful",
            "version": version,
            "system_user": system_user,
        }))
    })
    .await;

    match result {
        Ok(Ok(details)) => Finding::new(host, "mssql", "access", CheckStatus::Success, Severity::Info, details),
        Ok(Err(e)) => {
            let msg = e.to_string().to_lowercase();
            let status = if msg.contains("login failed") || msg.contains("auth") || msg.contains("denied") {
                CheckStatus::AccessDenied
            } else {
                CheckStatus::Error
            };
            Finding::new(host, "mssql", "access", status, Severity::Info, serde_json::json!({ "message": e.to_string() }))
        }
        Err(_) => Finding::new(host, "mssql", "access", CheckStatus::Unreachable, Severity::Info, serde_json::json!({ "message": "timeout" })),
    }
}

/// Check MSSQL access via nxc. Used on non-Windows platforms (tiberius has no
/// SSPI client there) and for NTLM-hash auth. Secrets are never stored.
pub async fn check_nxc(nxc: &crate::nxc::NxcHandle, host: &str, creds: &Credentials) -> Finding {
    let mut args: Vec<&str> = vec!["mssql", host];
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
            let user_up = creds.username.to_uppercase();
            let ok_line = stdout.lines().any(|l| l.contains("[+]") && l.to_uppercase().contains(&user_up));
            let denied_line = stdout.lines().any(|l| l.contains("[-]"));
            if ok_line {
                Finding::new(host, "mssql", "access", CheckStatus::Success, Severity::Info,
                    serde_json::json!({ "message": "MSSQL authentication successful (nxc)" }))
            } else if denied_line {
                Finding::new(host, "mssql", "access", CheckStatus::AccessDenied, Severity::Info,
                    serde_json::json!({ "message": "MSSQL authentication denied (nxc)" }))
            } else {
                Finding::new(host, "mssql", "access", CheckStatus::Error, Severity::Info,
                    serde_json::json!({ "message": "nxc mssql check returned no clear result" }))
            }
        }
        Err(e) => Finding::new(host, "mssql", "access", CheckStatus::Error, Severity::Info,
            serde_json::json!({ "message": format!("nxc invocation failed: {}", e) })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn sql_config_builds_with_windows_auth() {
        let c = Credentials::with_password("sa", "Passw0rd!", false);
        // Config must build without error; host/port accessors are private in tiberius.
        assert!(build_config("10.0.0.5", 1433, &c, "CORP").is_ok());
    }

    #[test]
    fn hash_auth_rejected_natively() {
        let c = Credentials::hash("sa", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0");
        assert!(build_config("10.0.0.5", 1433, &c, "CORP").is_err());
    }
}
