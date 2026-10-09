//! Minimal, dependency-free PDF report generator.
//!
//! Produces a clean multi-page text report (Helvetica, letter size) without
//! any external tool or C library - the output opens in any PDF viewer.

use super::ReportData;
use crate::findings::CheckStatus;
use anyhow::{Context, Result};
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

const PAGE_W: usize = 612; // letter, points
const PAGE_H: usize = 792;
const MARGIN: usize = 50;
const FONT_SIZE: usize = 9;
const LEADING: usize = 13;
const LINES_PER_PAGE: usize = (PAGE_H - 2 * MARGIN) / LEADING - 2;

/// Escape a string for a PDF literal text object and restrict to WinAnsi-safe
/// characters (map everything else to a placeholder).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\\' => "\\\\".to_string(),
            '(' => "\\(".to_string(),
            ')' => "\\)".to_string(),
            c if (c as u32) >= 0x20 && (c as u32) <= 0x7e => c.to_string(),
            '\t' => "    ".to_string(),
            _ => "?".to_string(),
        })
        .collect()
}

/// Render the report text lines, paginate, and write a valid PDF.
pub fn write_pdf(data: &ReportData, path: &Path, include_hashes: bool) -> Result<()> {
    let lines = build_lines(data, include_hashes);
    let bytes = render_pdf(&lines);
    let mut f = std::fs::File::create(path).context("cannot create pdf")?;
    f.write_all(&bytes)?;
    Ok(())
}

/// Assemble the flat list of report lines.
fn build_lines(data: &ReportData, include_hashes: bool) -> Vec<String> {
    let mut l: Vec<String> = Vec::new();
    let rule = "-".repeat(PAGE_W / FONT_SIZE - 8);
    let thick = "=".repeat(PAGE_W / FONT_SIZE - 8);

    l.push(String::new());
    l.push(center("easy-ad - Active Directory enumeration report", PAGE_W / FONT_SIZE - 8));
    l.push(center(
        &format!("domain {} | dc {} | generated {}", data.domain, data.dc, data.started.format("%Y-%m-%d %H:%M UTC")),
        PAGE_W / FONT_SIZE - 8,
    ));
    l.push(String::new());
    l.push(thick.clone());

    // ---- Executive summary ----
    l.push(String::new());
    l.push("EXECUTIVE SUMMARY".to_string());
    l.push(rule.clone());
    let sev_counts = crate::findings::ScanResults::count_by_severity(&data.findings);
    let mut summary = format!(
        "Hosts scanned: {} ({} up) | Total findings: {} | Attack paths: {}",
        data.hosts.len(),
        data.hosts_up(),
        data.findings.len(),
        data.attack_paths().len()
    );
    if !sev_counts.is_empty() {
        let parts: Vec<String> = sev_counts
            .iter()
            .map(|(s, n)| format!("{}: {}", s, n))
            .collect();
        summary.push_str(&format!(" | By severity: {}", parts.join(", ")));
    }
    l.push(summary);
    l.push(String::new());

    // ---- Hosts ----
    l.push("HOSTS".to_string());
    l.push(rule.clone());
    for h in &data.hosts {
        if h.open_ports.is_empty() {
            l.push(format!("{:<16} (no AD ports open)", h.ip));
        } else {
            let ports: Vec<String> = h.open_ports.iter().map(|p| p.to_string()).collect();
            l.push(format!("{:<16} ports: {}", h.ip, ports.join(", ")));
        }
    }
    l.push(String::new());

    // ---- Attack paths ----
    l.push("ATTACK PATHS".to_string());
    l.push(rule.clone());
    if data.attack_paths().is_empty() {
        l.push("None discovered.".to_string());
    }
    for f in data.attack_paths() {
        l.push(format!(
            "[{}] {} on {} ({}): {}",
            f.severity.to_string().to_uppercase(),
            f.check,
            f.target,
            f.protocol,
            compact_details(&f.details, include_hashes)
        ));
    }
    l.push(String::new());

    // ---- Per-host findings ----
    l.push("PER-HOST FINDINGS".to_string());
    l.push(rule.clone());
    for f in &data.findings {
        if f.status == CheckStatus::Vulnerable {
            continue; // already listed above
        }
        l.push(format!(
            "{:<16} {:<8} {:<12} {}",
            f.target,
            f.protocol,
            f.check,
            f.status
        ));
    }
    l.push(String::new());

    // ---- Shares ----
    if !data.shares.is_empty() {
        l.push("SHARE PERMISSIONS".to_string());
        l.push(rule.clone());
        l.push(format!(
            "{:<16} {:<24} {:<6} {:<6} {:<8} remark",
            "host", "share", "read", "write", "exec"
        ));
        for s in &data.shares {
            l.push(format!(
                "{:<16} {:<24} {:<6} {:<6} {:<8} {}",
                s.host,
                s.share,
                yes_no(s.perms.read),
                yes_no(s.perms.write),
                yes_no(s.perms.execute),
                s.remark
            ));
        }
        l.push(String::new());
    }

    // ---- Accounts ----
    if !data.accounts.is_empty() {
        l.push("ACCOUNTS (parsed from LDAP)".to_string());
        l.push(rule.clone());
        for a in &data.accounts {
            let flag = if a.enabled { "" } else { " [disabled]" };
            l.push(format!("{:<28} {:<16}{}", a.username, a.account_type, flag));
        }
        l.push(String::new());
    }

    // ---- Severity legend ----
    l.push(thick);
    l.push("Generated by easy-ad. Only run against systems you are authorized to test.".to_string());
    l
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn center(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        let total = width - s.len();
        let left = total / 2;
        let right = total - left;
        format!("{}{}{}", " ".repeat(left), s, " ".repeat(right))
    }
}

/// One-line rendering of finding details for the PDF.
fn compact_details(details: &serde_json::Value, include_hashes: bool) -> String {
    let mut parts = Vec::new();
    if let Some(obj) = details.as_object() {
        for (k, v) in obj {
            if !include_hashes && (k.contains("hash") || k.contains("ticket")) {
                parts.push(format!("{}: [redacted, use --include-hashes]", k));
                continue;
            }
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let val = if val.len() > 120 { format!("{}...", &val[..120]) } else { val };
            parts.push(format!("{}: {}", k, val));
        }
    }
    parts.join("; ")
}

// ---------------------------------------------------------------------------
// PDF serialization
// ---------------------------------------------------------------------------

fn render_pdf(lines: &[String]) -> Vec<u8> {
    let pages: Vec<&[String]> = lines.chunks(LINES_PER_PAGE).collect();
    let mut buf: Vec<u8> = Vec::new();
    let mut offsets: Vec<usize> = Vec::new();

    buf.extend_from_slice(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");

    // Object numbering:
    //   1: catalog, 2: pages, 3: font
    //   4 + i*2: page i, 5 + i*2: content i
    let page_obj_ids: Vec<usize> = (0..pages.len()).map(|i| 4 + i * 2).collect();

    let obj = |buf: &mut Vec<u8>, offsets: &mut Vec<usize>, id: usize, body: &str| {
        offsets.push(buf.len());
        let _ = writeln!(buf, "{} 0 obj\n{}\nendobj", id, body);
    };

    obj(&mut buf, &mut offsets, 1, "<< /Type /Catalog /Pages 2 0 R >>");
    let kids: Vec<String> = page_obj_ids.iter().map(|id| format!("{} 0 R", id)).collect();
    obj(
        &mut buf,
        &mut offsets,
        2,
        &format!("<< /Type /Pages /Kids [{}] /Count {} >>", kids.join(" "), pages.len()),
    );
    obj(
        &mut buf,
        &mut offsets,
        3,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    );

    for (i, chunk) in pages.iter().enumerate() {
        let page_id = 4 + i * 2;
        let content_id = page_id + 1;
        let stream = page_stream(chunk, i + 1, pages.len());
        obj(
            &mut buf,
            &mut offsets,
            page_id,
            &format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] \
                 /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>",
                PAGE_W, PAGE_H, content_id
            ),
        );
        offsets.push(buf.len());
        let _ = writeln!(buf, "{} 0 obj", content_id);
        let _ = writeln!(buf, "<< /Length {} >>", stream.len());
        let _ = writeln!(buf, "stream");
        buf.extend_from_slice(stream.as_bytes());
        let _ = writeln!(buf, "endstream\nendobj");
    }

    // xref + trailer
    let xref_start = buf.len();
    let count = 3 + pages.len() * 2;
    let _ = writeln!(buf, "xref\n0 {}", count + 1);
    let _ = writeln!(buf, "0000000000 65535 f ");
    for &off in &offsets {
        let _ = writeln!(buf, "{:010} 00000 n ", off);
    }
    let _ = writeln!(
        buf,
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF",
        count + 1,
        xref_start
    );
    buf
}

fn page_stream(lines: &[String], page_no: usize, total: usize) -> String {
    let mut s = String::new();
    s.push_str("BT\n");
    let _ = writeln!(s, "/F1 {} Tf", FONT_SIZE);
    let _ = writeln!(s, "{} TL", LEADING);
    let _ = writeln!(s, "1 0 0 1 {} {} Tm", MARGIN, PAGE_H - MARGIN);
    for line in lines {
        let _ = writeln!(s, "({}) Tj T*", sanitize(line));
    }
    // Footer with page number.
    let _ = writeln!(s, "1 0 0 1 {} {} Tm", MARGIN, MARGIN - 20);
    let _ = writeln!(s, "(easy-ad | page {} of {}) Tj", page_no, total);
    s.push_str("ET");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    #[test]
    fn sanitizes_pdf_specials() {
        assert_eq!(sanitize("a(b)\\c"), "a\\(b\\)\\\\c");
        assert_eq!(sanitize("tab\there"), "tab    here");
        assert_eq!(sanitize("caf\u{e9}"), "caf?");
    }

    #[test]
    fn centers_text() {
        let c = center("hi", 10);
        assert_eq!(c.len(), 10);
        assert_eq!(c, "    hi    ");
    }

    #[test]
    fn pdf_starts_and_ends_correctly() {
        let bytes = render_pdf(&["hello".to_string()]);
        assert!(bytes.starts_with(b"%PDF-1.4"));
        assert!(bytes.windows(5).any(|w| w == b"%%EOF"));
        assert!(String::from_utf8_lossy(&bytes).contains("(hello) Tj"));
    }

    #[test]
    fn redacts_hashes_by_default() {
        let details = serde_json::json!({ "hash": "krb5tgs$...", "account": "svc" });
        let compact = compact_details(&details, false);
        assert!(compact.contains("[redacted"));
        assert!(!compact.contains("krb5tgs"));
        let compact2 = compact_details(&details, true);
        assert!(compact2.contains("krb5tgs"));
    }

    #[test]
    fn severity_display_used() {
        assert_eq!(Severity::High.to_string(), "high");
        assert_eq!(CheckStatus::AccessDenied.to_string(), "access_denied");
    }
}
