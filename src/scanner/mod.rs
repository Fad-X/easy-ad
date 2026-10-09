//! Native protocol scanners: LDAP, SMB, WinRM, RDP, MSSQL.
//!
//! Each scanner reports structured [`Finding`]s and never aborts the overall
//! scan on per-target errors - failures are logged and the pipeline continues.

pub mod ldap;
pub mod mssql;
pub mod rdp;
pub mod smb;
pub mod winrm;

use crate::auth::Credentials;
use std::time::Duration;

/// Shared context handed to every scanner.
#[derive(Debug, Clone)]
pub struct ScanContext {
    pub creds: Option<Credentials>,
    pub domain: String,
    /// Domain controller IP/hostname used for LDAP/Kerberos.
    pub dc: String,
    pub base_dn: String,
    pub timeout: Duration,
}

impl ScanContext {
    pub fn new(
        creds: Option<Credentials>,
        domain: impl Into<String>,
        dc: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        let domain = domain.into();
        let base_dn = crate::discovery::domain_to_base_dn(&domain);
        ScanContext { creds, domain, dc: dc.into(), base_dn, timeout }
    }
}
