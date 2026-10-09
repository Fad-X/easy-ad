//! easy-ad: fast, automated Active Directory enumeration and attack-path scanner.
//!
//! Orchestrates native Rust protocol clients (LDAP, SMB, WinRM, MSSQL, RDP)
//! and falls back to NetExec (nxc) for checks that require full protocol
//! implementations not yet feasible in native Rust (e.g. Kerberos ticket
//! acquisition). Produces BloodHound CE compatible data and structured
//! JSON / PDF reports.

pub mod attack_paths;
pub mod auth;
pub mod bloodhound;
pub mod cli;
pub mod discovery;
pub mod findings;
pub mod nxc;
pub mod report;
pub mod scanner;

pub use cli::Cli;
pub use findings::{Finding, Severity, ScanResults};
