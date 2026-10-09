//! Shared finding / result model used across all scanners and reporters.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Severity classification for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome classification for a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Authentication succeeded and data was collected.
    Success,
    /// The target is exposed and vulnerable to the specific check.
    Vulnerable,
    /// Authentication / access was denied.
    AccessDenied,
    /// The service is reachable but the check returned nothing notable.
    NotVulnerable,
    /// The service is not reachable on this host.
    Unreachable,
    /// The check itself failed (network error, parse error, ...). Logged, scan continues.
    Error,
}

impl CheckStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckStatus::Success => "success",
            CheckStatus::Vulnerable => "vulnerable",
            CheckStatus::AccessDenied => "access_denied",
            CheckStatus::NotVulnerable => "not_vulnerable",
            CheckStatus::Unreachable => "unreachable",
            CheckStatus::Error => "error",
        }
    }
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single, structured finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub target: String,
    pub protocol: String,
    pub check: String,
    pub status: CheckStatus,
    pub severity: Severity,
    /// Free-form structured detail payload (paths, users, hashes, versions...).
    pub details: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    pub fn new(
        target: impl Into<String>,
        protocol: impl Into<String>,
        check: impl Into<String>,
        status: CheckStatus,
        severity: Severity,
        details: serde_json::Value,
    ) -> Self {
        Finding {
            target: target.into(),
            protocol: protocol.into(),
            check: check.into(),
            status,
            severity,
            details,
            timestamp: Utc::now(),
        }
    }

    /// Convenience: an informational success finding with a string detail.
    pub fn info(target: impl Into<String>, protocol: impl Into<String>, check: impl Into<String>, msg: impl Into<String>) -> Self {
        Finding::new(
            target,
            protocol,
            check,
            CheckStatus::Success,
            Severity::Info,
            serde_json::json!({ "message": msg.into() }),
        )
    }
}

/// Thread-safe accumulator for all findings produced during a scan.
#[derive(Debug, Default)]
pub struct ScanResults {
    inner: Mutex<Vec<Finding>>,
}

impl ScanResults {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, finding: Finding) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        tracing::info!(
            target = %finding.target,
            protocol = %finding.protocol,
            check = %finding.check,
            status = %finding.status,
            severity = %finding.severity,
            "finding"
        );
        guard.push(finding);
    }

    pub fn extend(&self, findings: Vec<Finding>) {
        for f in findings {
            self.push(f);
        }
    }

    pub fn all(&self) -> Vec<Finding> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.sort_by(|a, b| {
            a.target
                .cmp(&b.target)
                .then(a.protocol.cmp(&b.protocol))
                .then(a.check.cmp(&b.check))
        });
        std::mem::take(&mut *guard)
    }

    pub fn count_by_severity(findings: &[Finding]) -> Vec<(Severity, usize)> {
        let mut counts: Vec<(Severity, usize)> = Vec::new();
        for sev in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let n = findings.iter().filter(|f| f.severity == sev).count();
            if n > 0 {
                counts.push((sev, n));
            }
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn results_accumulate_thread_safe() {
        let r = ScanResults::new();
        r.push(Finding::info("10.0.0.1", "smb", "access", "ok"));
        r.push(Finding::info("10.0.0.2", "ldap", "bind", "ok"));
        assert_eq!(r.all().len(), 2);
    }
}
