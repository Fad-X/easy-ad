//! Attack-path checks: Kerberoasting, AS-REP Roasting, Pre2k, coercion, gMSA.
//!
//! Discovery (LDAP filters) runs natively in Rust; ticket/hash acquisition
//! requires a full Kerberos client and is delegated to nxc, which is
//! auto-installed when missing.

pub mod asreproast;
pub mod coercion;
pub mod gmsa;
pub mod kerberoast;
pub mod pre2k;

use crate::auth::Credentials;
use anyhow::Result;
use std::path::Path;

/// Shared inputs for every attack-path check.
pub struct AttackContext<'a> {
    pub creds: &'a Credentials,
    pub domain: &'a str,
    pub dc: &'a str,
    pub ldap: &'a crate::scanner::ldap::LdapClient,
    pub nxc: Option<&'a crate::nxc::NxcHandle>,
    /// Directory where hash/ticket files are written.
    pub out_dir: &'a Path,
}

impl<'a> AttackContext<'a> {
    /// Base DN derived from the scan domain.
    pub fn ldap_base_dn(&self) -> String {
        crate::discovery::domain_to_base_dn(self.domain)
    }

    /// nxc `-u <user> -p <pass>` or `-u <user> -H <nthash>` argument vector.
    pub fn nxc_secret_args(&self) -> Vec<String> {
        match self.creds.password() {
            Some(p) => vec!["-u".into(), self.creds.username.clone(), "-p".into(), p.to_string()],
            None => vec![
                "-u".into(),
                self.creds.username.clone(),
                "-H".into(),
                self.creds.secret.nt_part().unwrap_or_default(),
            ],
        }
    }
}

/// Write a hash/ticket capture file under the run's output directory.
pub fn write_capture(out_dir: &Path, name: &str, data: &str) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(out_dir)?;
    let path = out_dir.join(name);
    std::fs::write(&path, data)?;
    Ok(path)
}

/// Require nxc for a check; returns Err with a clear message if unavailable.
pub fn require_nxc(nxc: Option<&crate::nxc::NxcHandle>) -> Result<&crate::nxc::NxcHandle> {
    nxc.ok_or_else(|| anyhow::anyhow!("nxc unavailable; install with: pipx install netexec"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_selection_picks_password_or_hash() {
        let c = Credentials::with_password("alice", "s3cret", false);
        assert_eq!(c.password(), Some("s3cret"));
        let h = Credentials::hash(
            "alice",
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        );
        assert!(h.password().is_none());
        assert_eq!(h.secret.nt_part().unwrap(), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }
}
