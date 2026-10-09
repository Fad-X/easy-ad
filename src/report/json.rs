//! Structured JSON output: hosts, users, shares, attack_paths, credentials.

use super::ReportData;
use anyhow::{Context, Result};
use serde_json::json;
use std::path::{Path, PathBuf};

/// Write the per-category JSON files; returns the written paths.
pub fn write_json_outputs(data: &ReportData, out_dir: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(out_dir).context("cannot create output dir")?;
    let mut written = Vec::new();

    let files: Vec<(&str, serde_json::Value)> = vec![
        ("hosts", json!(data.hosts)),
        ("users", json!(data.accounts)),
        ("shares", json!(data.shares)),
        (
            "attack_paths",
            json!(data
                .attack_paths()
                .into_iter()
                .map(|f| serde_json::to_value(f).unwrap_or_default())
                .collect::<Vec<_>>()),
        ),
        (
            "credentials",
            json!(data
                .credentials
                .iter()
                .map(|c| json!({
                    "username": c.username,
                    "auth_type": c.auth_type,
                    "kerberos": c.kerberos,
                }))
                .collect::<Vec<_>>()),
        ),
        (
            "findings",
            json!(data
                .findings
                .iter()
                .map(|f| serde_json::to_value(f).unwrap_or_default())
                .collect::<Vec<_>>()),
        ),
    ];

    for (name, value) in files {
        let path = out_dir.join(format!("{}.json", name));
        std::fs::write(&path, serde_json::to_string_pretty(&value)?)?;
        written.push(path);
    }
    Ok(written)
}
