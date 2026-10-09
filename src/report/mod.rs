//! Report generation: JSON findings output and PDF report.

pub mod json;
pub mod pdf;

use crate::auth::CredentialRecord;
use crate::discovery::parser::{ParsedAccount, ShareEntry};
use crate::findings::Finding;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// A host record for reports.
#[derive(Debug, Clone, Serialize)]
pub struct HostRecord {
    pub ip: String,
    pub open_ports: Vec<u16>,
}

/// Everything the reporters need, assembled once after scanning.
#[derive(Debug)]
pub struct ReportData {
    pub domain: String,
    pub dc: String,
    pub started: DateTime<Utc>,
    pub hosts: Vec<HostRecord>,
    pub accounts: Vec<ParsedAccount>,
    pub shares: Vec<ShareEntry>,
    pub findings: Vec<Finding>,
    pub credentials: Vec<CredentialRecord>,
    pub bloodhound_zip: Option<PathBuf>,
}

impl ReportData {
    /// Findings that represent discovered attack paths (vulnerable status).
    pub fn attack_paths(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| matches!(f.status, crate::findings::CheckStatus::Vulnerable))
            .collect()
    }

    /// Hosts considered "up" during the scan.
    pub fn hosts_up(&self) -> usize {
        self.hosts.iter().filter(|h| !h.open_ports.is_empty()).count()
    }
}

/// Write the full report set into `out_dir` according to format flags.
pub fn write_reports(
    data: &ReportData,
    out_dir: &Path,
    want_json: bool,
    want_pdf: bool,
    include_hashes: bool,
) -> Result<Vec<PathBuf>> {
    let mut written = Vec::new();
    if want_json {
        written.extend(json::write_json_outputs(data, out_dir)?);
    }
    if want_pdf {
        let pdf_path = out_dir.join("easy-ad-report.pdf");
        pdf::write_pdf(data, &pdf_path, include_hashes)?;
        written.push(pdf_path);
    }
    Ok(written)
}
