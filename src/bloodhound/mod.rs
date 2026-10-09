//! BloodHound CE compatible JSON collection, built natively from LDAP data.
//!
//! Collects users, groups, computers, OUs, GPOs, trusts, sessions, SPNs and
//! delegation data in a single LDAP pass and emits BloodHound Community
//! Edition import files (v5 format).

pub mod ingest;

use crate::scanner::ldap::{LdapClient, LdapData};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Parse a binary `objectSid` attribute value into its string form
/// (`S-1-5-21-...-RID`).
pub fn parse_sid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 || bytes[0] != 1 {
        return None;
    }
    let subauth_count = bytes[1] as usize;
    if bytes.len() < 8 + subauth_count * 4 {
        return None;
    }
    let mut authority: u64 = 0;
    for b in &bytes[2..8] {
        authority = (authority << 8) | (*b as u64);
    }
    let mut sid = format!("S-{}-{}", bytes[0], authority);
    for i in 0..subauth_count {
        let start = 8 + i * 4;
        let sub = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]);
        sid.push_str(&format!("-{}", sub));
    }
    Some(sid)
}

/// Domain portion of an account SID (all but the last sub-authority).
pub fn domain_sid(account_sid: &str) -> Option<String> {
    let parts: Vec<&str> = account_sid.split('-').collect();
    if parts.len() < 4 {
        return None;
    }
    Some(parts[..parts.len() - 1].join("-"))
}

/// Convert an AD FILETIME (100ns ticks since 1601-01-01) to Unix epoch seconds.
pub fn filetime_to_epoch(ft: &str) -> i64 {
    ft.parse::<i64>()
        .map(|v| v / 10_000_000 - 11_644_473_600)
        .unwrap_or(0)
}

/// Collect the binary objectSid of an entry.
fn entry_sid(entry: &ldap3::SearchEntry) -> Option<String> {
    entry
        .bin_attrs
        .get("objectSid")
        .and_then(|v| v.first())
        .and_then(|b| parse_sid(b))
}

fn attr(entry: &ldap3::SearchEntry, name: &str) -> String {
    LdapClient::attr(entry, name).unwrap_or("").to_string()
}

fn attrs(entry: &ldap3::SearchEntry, name: &str) -> Vec<String> {
    LdapClient::attrs(entry, name).iter().map(|s| s.to_string()).collect()
}

fn u32_attr(entry: &ldap3::SearchEntry, name: &str) -> u32 {
    LdapClient::attr(entry, name).and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// BloodHound users.json
pub fn build_users(data: &LdapData, domain: &str) -> Value {
    let domain_upper = domain.to_uppercase();
    let items: Vec<Value> = data
        .users
        .iter()
        .filter_map(|e| {
            let sid = entry_sid(e)?;
            let uac = u32_attr(e, "userAccountControl");
            Some(json!({
                "PrimaryGroupSID": primary_group_sid(&sid, u32_attr(e, "primaryGroupID")),
                "ObjectIdentifier": sid,
                "Properties": {
                    "name": format!("{}@{}", attr(e, "sAMAccountName").to_uppercase(), domain_upper),
                    "distinguishedname": attr(e, "distinguishedName"),
                    "domain": domain_upper,
                    "enabled": uac & 0x2 == 0,
                    "lastlogon": filetime_to_epoch(&attr(e, "lastLogon")),
                    "pwdlastset": filetime_to_epoch(&attr(e, "pwdLastSet")),
                    "serviceprincipalnames": attrs(e, "servicePrincipalName"),
                    "hasspn": !attrs(e, "servicePrincipalName").is_empty(),
                    "displayname": attr(e, "displayName"),
                    "email": attr(e, "userPrincipalName"),
                    "description": attr(e, "description"),
                    "admincount": u32_attr(e, "adminCount") == 1,
                    "dontreqpreauth": uac & 0x400000 != 0,
                    "passwordnotreqd": uac & 0x20 != 0,
                    "unconstraineddelegation": uac & 0x80000 != 0,
                    "sensitive": uac & 0x100000 != 0,
                    "samaccountname": attr(e, "sAMAccountName"),
                },
                "SPNs": attrs(e, "servicePrincipalName"),
                "Aces": [],
                "IsACLProtected": false,
                "IsDeleted": false,
                "HasSIDHistory": false,
            }))
        })
        .collect();
    bh_file("users", items)
}

fn primary_group_sid(account_sid: &str, primary_group_id: u32) -> String {
    domain_sid(account_sid)
        .map(|ds| format!("{}-{}", ds, primary_group_id))
        .unwrap_or_default()
}

/// BloodHound groups.json (members resolved DN -> SID using the collected maps).
pub fn build_groups(data: &LdapData, domain: &str) -> Value {
    let domain_upper = domain.to_uppercase();
    let dn_map = dn_to_sid_map(data);
    let items: Vec<Value> = data
        .groups
        .iter()
        .filter_map(|e| {
            let sid = entry_sid(e)?;
            let members: Vec<Value> = attrs(e, "member")
                .iter()
                .filter_map(|dn| {
                    dn_map.get(dn).map(|msid| {
                        json!({ "ObjectIdentifier": msid, "ObjectType": "Unknown" })
                    })
                })
                .collect();
            Some(json!({
                "ObjectIdentifier": sid,
                "Properties": {
                    "name": format!("{}@{}", attr(e, "sAMAccountName").to_uppercase(), domain_upper),
                    "distinguishedname": attr(e, "distinguishedName"),
                    "domain": domain_upper,
                    "admincount": u32_attr(e, "adminCount") == 1,
                    "description": attr(e, "description"),
                },
                "Members": members,
                "Aces": [],
                "IsACLProtected": false,
                "IsDeleted": false,
            }))
        })
        .collect();
    bh_file("groups", items)
}

/// BloodHound computers.json
pub fn build_computers(data: &LdapData, domain: &str) -> Value {
    let domain_upper = domain.to_uppercase();
    let items: Vec<Value> = data
        .computers
        .iter()
        .filter_map(|e| {
            let sid = entry_sid(e)?;
            let uac = u32_attr(e, "userAccountControl");
            Some(json!({
                "ObjectIdentifier": sid,
                "PrimaryGroupSID": primary_group_sid(&sid, u32_attr(e, "primaryGroupID")),
                "Properties": {
                    "name": attr(e, "dNSHostName").to_uppercase(),
                    "distinguishedname": attr(e, "distinguishedName"),
                    "domain": domain_upper,
                    "enabled": uac & 0x2 == 0,
                    "operatingsystem": attr(e, "operatingSystem"),
                    "operatingsystemversion": attr(e, "operatingSystemVersion"),
                    "lastlogon": filetime_to_epoch(&attr(e, "lastLogon")),
                    "samaccountname": attr(e, "sAMAccountName"),
                    "unconstraineddelegation": uac & 0x80000 != 0,
                    "trustedtoauth": uac & 0x1000000 != 0,
                },
                "Sessions": [],
                "PrivilegedSessions": [],
                "RegistrySessions": [],
                "Aces": [],
                "AllowedToDelegate": [],
                "AllowedToAct": [],
                "HasSIDHistory": [],
                "IsDeleted": false,
                "IsACLProtected": false,
            }))
        })
        .collect();
    bh_file("computers", items)
}

/// BloodHound ous.json
pub fn build_ous(data: &LdapData, domain: &str) -> Value {
    let domain_upper = domain.to_uppercase();
    let items: Vec<Value> = data
        .ous
        .iter()
        .map(|e| {
            json!({
                "ObjectIdentifier": attr(e, "distinguishedName"),
                "Properties": {
                    "name": format!("{}@{}", attr(e, "name"), domain_upper),
                    "distinguishedname": attr(e, "distinguishedName"),
                    "domain": domain_upper,
                    "description": attr(e, "description"),
                },
                "Links": [],
                "ChildObjects": [],
                "Aces": [],
                "IsDeleted": false,
                "IsACLProtected": false,
            })
        })
        .collect();
    bh_file("ous", items)
}

/// BloodHound gpos.json
pub fn build_gpos(data: &LdapData, domain: &str) -> Value {
    let domain_upper = domain.to_uppercase();
    let items: Vec<Value> = data
        .gpos
        .iter()
        .map(|e| {
            json!({
                "ObjectIdentifier": attr(e, "distinguishedName"),
                "Properties": {
                    "name": format!("{}@{}", attr(e, "displayName").to_uppercase(), domain_upper),
                    "distinguishedname": attr(e, "distinguishedName"),
                    "domain": domain_upper,
                    "gpcpath": attr(e, "gPCFileSysPath"),
                },
                "Links": [],
                "Aces": [],
                "IsDeleted": false,
                "IsACLProtected": false,
            })
        })
        .collect();
    bh_file("gpos", items)
}

/// BloodHound domains.json (with domain SID + trust edges).
pub fn build_domains(data: &LdapData, domain: &str) -> Value {
    let domain_upper = domain.to_uppercase();
    let sid = data.domain.first().and_then(entry_sid);
    let distinguished = data
        .domain
        .first()
        .map(|e| attr(e, "distinguishedName"))
        .unwrap_or_default();
    let items: Vec<Value> = vec![json!({
        "ObjectIdentifier": sid.clone().unwrap_or_default(),
        "Properties": {
            "name": domain_upper,
            "distinguishedname": distinguished,
            "domain": domain_upper,
        },
        "Trusts": build_trust_edges(data),
        "Aces": [],
        "Links": [],
        "ChildObjects": [],
        "GPOChanges": {},
        "IsDeleted": false,
        "IsACLProtected": false,
    })];
    bh_file("domains", items)
}

fn build_trust_edges(data: &LdapData) -> Vec<Value> {
    data.trusts
        .iter()
        .map(|e| {
            json!({
                "TargetDomainName": attr(e, "trustPartner"),
                "TargetDomainSid": null,
                "TrustDirection": u32_attr(e, "trustDirection"),
                "TrustType": u32_attr(e, "trustType"),
                "IsTransitive": false,
            })
        })
        .collect()
}

/// Build a DN -> SID map from all collected entries (users, groups, computers).
fn dn_to_sid_map(data: &LdapData) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for e in data.users.iter().chain(&data.groups).chain(&data.computers) {
        if let Some(sid) = entry_sid(e) {
            map.insert(e.dn.clone(), sid);
        }
    }
    map
}

/// Wrap collected items in the BH file envelope with meta.
fn bh_file(kind: &str, items: Vec<Value>) -> Value {
    let count = items.len();
    json!({
        "data": items,
        "meta": {
            "methods": 0,
            "type": kind,
            "count": count,
            "version": 5,
        }
    })
}

/// Write all BloodHound JSON files into `out_dir` and return the file list.
pub fn write_bloodhound_json(data: &LdapData, domain: &str, out_dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    std::fs::create_dir_all(out_dir).context("cannot create bloodhound output dir")?;
    let files: Vec<(&str, Value)> = vec![
        ("users.json", build_users(data, domain)),
        ("groups.json", build_groups(data, domain)),
        ("computers.json", build_computers(data, domain)),
        ("ous.json", build_ous(data, domain)),
        ("gpos.json", build_gpos(data, domain)),
        ("domains.json", build_domains(data, domain)),
    ];
    let mut written = Vec::new();
    for (name, value) in files {
        let path = out_dir.join(name);
        std::fs::write(&path, serde_json::to_string_pretty(&value)?)?;
        written.push(path);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binary_sid() {
        // S-1-5-21-1234567890-1234567890-1234567890-1105
        // (identifier authority 5, then sub-auths: 21, x, y, z, rid)
        let mut bytes = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1234567890, 1234567890, 1234567890, 1105] {
            bytes.extend_from_slice(&sub.to_le_bytes());
        }
        assert_eq!(
            parse_sid(&bytes).unwrap(),
            "S-1-5-21-1234567890-1234567890-1234567890-1105"
        );
    }

    #[test]
    fn domain_sid_strips_rid() {
        assert_eq!(
            domain_sid("S-1-5-21-1-2-3-1105").unwrap(),
            "S-1-5-21-1-2-3"
        );
    }

    #[test]
    fn filetime_conversion() {
        // FILETIME 13348464000_0000000 ticks == 2023-12-31T02:40:00Z.
        let ft = "133484640000000000";
        assert_eq!(filetime_to_epoch(ft), 1703990400);
    }

    #[test]
    fn envelope_has_meta() {
        let v = bh_file("users", vec![json!({"x": 1})]);
        assert_eq!(v["meta"]["type"], "users");
        assert_eq!(v["meta"]["count"], 1);
        assert_eq!(v["meta"]["version"], 5);
    }
}
