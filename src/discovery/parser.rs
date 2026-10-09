//! Username & share output parsing.
//!
//! Turns raw LDAP / nxc output into structured, deduplicated account and
//! share-permission records that feed back into attack-path checks.

use serde::{Deserialize, Serialize};

/// Classification of an AD account discovered via LDAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountType {
    User,
    Computer,
    Service,
    Gmsa,
}

impl AccountType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AccountType::User => "user",
            AccountType::Computer => "computer",
            AccountType::Service => "service_account",
            AccountType::Gmsa => "gmsa",
        }
    }
}

impl std::fmt::Display for AccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed, deduplicated AD account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedAccount {
    pub username: String,
    pub account_type: AccountType,
    pub enabled: bool,
    pub spns: Vec<String>,
    pub description: Option<String>,
}

/// Raw LDAP user entry shape consumed by [`parse_accounts`].
/// (ldap3 `SearchEntry` is converted into this minimal form first.)
#[derive(Debug, Clone, Default)]
pub struct RawAccount {
    pub sam_account_name: Option<String>,
    pub user_account_control: Option<u32>,
    pub service_principal_names: Vec<String>,
    pub description: Option<String>,
    pub object_classes: Vec<String>,
}

const UAC_ACCOUNTDISABLE: u32 = 0x0002;

/// Classify a single account from its raw attributes.
pub fn classify(raw: &RawAccount) -> Option<ParsedAccount> {
    let name = raw.sam_account_name.clone()?;
    if name.is_empty() {
        return None;
    }
    let is_gmsa = raw
        .object_classes
        .iter()
        .any(|c| c.eq_ignore_ascii_case("msDS-GroupManagedServiceAccount"));
    let is_computer = raw
        .object_classes
        .iter()
        .any(|c| c.eq_ignore_ascii_case("computer"))
        || name.ends_with('$');
    let account_type = if is_gmsa {
        AccountType::Gmsa
    } else if is_computer {
        AccountType::Computer
    } else if !raw.service_principal_names.is_empty() {
        AccountType::Service
    } else {
        AccountType::User
    };
    let enabled = raw
        .user_account_control
        .map(|uac| uac & UAC_ACCOUNTDISABLE == 0)
        .unwrap_or(true);
    Some(ParsedAccount {
        username: name,
        account_type,
        enabled,
        spns: raw.service_principal_names.clone(),
        description: raw.description.clone(),
    })
}

/// Parse + deduplicate a set of raw LDAP accounts, sorted for stable output.
pub fn parse_accounts(raws: &[RawAccount]) -> Vec<ParsedAccount> {
    let mut accounts: Vec<ParsedAccount> = raws.iter().filter_map(classify).collect();
    accounts.sort_by(|a, b| a.username.to_lowercase().cmp(&b.username.to_lowercase()));
    accounts.dedup_by(|a, b| a.username.eq_ignore_ascii_case(&b.username));
    accounts
}

/// Effective permissions a user has on an SMB share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharePerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl SharePerms {
    pub fn none() -> Self {
        SharePerms { read: false, write: false, execute: false }
    }
}

/// A parsed SMB share permission record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareEntry {
    pub host: String,
    pub share: String,
    pub remark: String,
    pub perms: SharePerms,
}

/// Parse the text output of `nxc smb <ip> -u <u> -p <p> --shares`.
///
/// Handles both tab-separated (`READ\t\\\\host\\share`) and columnar output
/// produced by different nxc versions.
pub fn parse_nxc_shares(host: &str, stdout: &str) -> Vec<ShareEntry> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("SMB") || line.starts_with('[') && line.contains("Shares") {
            continue;
        }
        let lower = line.to_lowercase();
        let perm_flags = ["read", "write", "execute", "rwd", "rd", "rw"];
        let has_perm_token = perm_flags.iter().any(|p| lower.contains(p));
        if !has_perm_token && !line.contains("\\\\") && !line.contains('\\') {
            continue;
        }
        let mut tokens: Vec<&str> = line.split('\t').collect();
        if tokens.len() == 1 {
            tokens = line.split_whitespace().collect();
        }
        // Permission token: first token containing a perm keyword, else "read".
        let mut read = false;
        let mut write = false;
        let mut execute = false;
        for t in &tokens {
            let tl = t.to_lowercase();
            if tl.contains("rwd") || tl.contains("read&write") {
                read = true;
                write = true;
            }
            if tl == "read" || tl == "rd" || tl.starts_with("read,") {
                read = true;
            }
            if tl.contains("write") {
                write = true;
            }
            if tl.contains("execute") {
                execute = true;
            }
        }
        // Share name: prefer the token containing a UNC or bare share name.
        let mut share_name = String::new();
        let mut remark_parts = Vec::new();
        for (i, t) in tokens.iter().enumerate() {
            let cleaned = t.trim_matches('"');
            if let Some(pos) = cleaned.rfind('\\') {
                share_name = cleaned[pos + 1..].trim_matches('"').to_string();
                break;
            }
            if i > 0 && !cleaned.is_empty() && share_name.is_empty() {
                // bare share token, e.g. "ADMIN$"
                share_name = cleaned.trim_matches('"').to_string();
            } else if !share_name.is_empty() {
                remark_parts.push(cleaned);
            }
        }
        if share_name.is_empty() {
            continue;
        }
        out.push(ShareEntry {
            host: host.to_string(),
            share: share_name.clone(),
            remark: remark_parts.join(" "),
            perms: SharePerms { read, write, execute },
        });
    }
    // Deduplicate by share name, keeping the most permissive entry.
    out.sort_by(|a, b| a.share.cmp(&b.share));
    out.dedup_by(|a, b| {
        if a.share == b.share {
            b.perms.read |= a.perms.read;
            b.perms.write |= a.perms.write;
            b.perms.execute |= a.perms.execute;
            true
        } else {
            false
        }
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(sam: &str, uac: Option<u32>, spns: &[&str], classes: &[&str]) -> RawAccount {
        RawAccount {
            sam_account_name: Some(sam.to_string()),
            user_account_control: uac,
            service_principal_names: spns.iter().map(|s| s.to_string()).collect(),
            description: None,
            object_classes: classes.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn classifies_account_types() {
        let accounts = vec![
            raw("alice", Some(0x200, ), &[], &["user", "person", "organizationalPerson"]),
            raw("WS01$", None, &[], &["computer"]),
            raw("svc_sql", None, &["MSSQLSvc/db.corp.local"], &["user"]),
            raw("gmsa_backup$", None, &[], &["user", "msDS-GroupManagedServiceAccount"]),
        ];
        let parsed = parse_accounts(&accounts);
        assert_eq!(parsed.len(), 4);
        // Sorted case-insensitively: alice, gmsa_backup$, svc_sql, WS01$.
        assert_eq!(parsed[0].username, "alice");
        assert_eq!(parsed[0].account_type, AccountType::User);
        assert_eq!(parsed[1].account_type, AccountType::Gmsa);
        assert_eq!(parsed[2].account_type, AccountType::Service);
        assert_eq!(parsed[3].account_type, AccountType::Computer);
    }

    #[test]
    fn disabled_flag_comes_from_uac() {
        let parsed = classify(&raw("alice", Some(0x202), &[], &["user"])).unwrap();
        assert!(!parsed.enabled);
        let parsed2 = classify(&raw("alice", Some(0x200), &[], &["user"])).unwrap();
        assert!(parsed2.enabled);
    }

    #[test]
    fn dedupes_case_insensitively() {
        let accounts = vec![raw("Alice", None, &[], &["user"]), raw("ALICE", None, &[], &["user"])];
        assert_eq!(parse_accounts(&accounts).len(), 1);
    }

    #[test]
    fn parses_nxc_share_table() {
        let stdout = "SMB        10.0.0.5    445    DC01   Shares\n\
                      READ\t\\\\DC01\\NETLOGON\tLogon server share\n\
                      READ,WRITE\t\\\\DC01\\SYSVOL\tLogon server share\n\
                      READ\t\\\\DC01\\ADMIN$\tRemote Admin\n";
        let shares = parse_nxc_shares("10.0.0.5", stdout);
        assert_eq!(shares.len(), 3);
        let netlogon = shares.iter().find(|s| s.share == "NETLOGON").unwrap();
        assert!(netlogon.perms.read && !netlogon.perms.write);
        let sysvol = shares.iter().find(|s| s.share == "SYSVOL").unwrap();
        assert!(sysvol.perms.read && sysvol.perms.write);
    }

    #[test]
    fn merges_duplicate_share_entries() {
        let stdout = "READ\t\\\\DC01\\IPC$\t\nWRITE\t\\\\DC01\\IPC$\t\n";
        let shares = parse_nxc_shares("10.0.0.5", stdout);
        assert_eq!(shares.len(), 1);
        assert!(shares[0].perms.read && shares[0].perms.write);
    }
}
