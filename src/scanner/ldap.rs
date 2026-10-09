//! LDAP queries and directory data collection (BloodHound source data).

use crate::auth::{Credentials, Secret};
use crate::discovery::parser::RawAccount;
use anyhow::{Context, Result, bail};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Query builders (pure functions - unit tested)
// ---------------------------------------------------------------------------

pub fn users_filter() -> &'static str {
    "(&(objectCategory=person)(objectClass=user))"
}

pub fn computers_filter() -> &'static str {
    "(&(objectClass=computer))"
}

pub fn groups_filter() -> &'static str {
    "(&(objectCategory=group))"
}

pub fn ous_filter() -> &'static str {
    "(&(objectClass=organizationalUnit))"
}

pub fn gpos_filter() -> &'static str {
    "(&(objectCategory=groupPolicyContainer))"
}

pub fn trusts_filter() -> &'static str {
    "(&(objectClass=trustedDomain))"
}

/// Accounts with SPNs set and not disabled -> Kerberoastable.
pub fn kerberoastable_filter() -> &'static str {
    "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
}

/// Accounts with DONT_REQ_PREAUTH set and not disabled -> AS-REP roastable.
pub fn asreproastable_filter() -> &'static str {
    "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
}

/// Pre-Windows-2000 computer accounts (uac 4128 = disabled + machine account).
pub fn pre2k_filter() -> &'static str {
    "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=4128))"
}

pub fn gmsa_filter() -> &'static str {
    "(&(objectClass=msDS-GroupManagedServiceAccount))"
}

pub fn domain_filter() -> &'static str {
    "(&(objectClass=domainDNS))"
}

pub const USER_ATTRS: &[&str] = &[
    "sAMAccountName",
    "userAccountControl",
    "servicePrincipalName",
    "description",
    "memberOf",
    "primaryGroupID",
    "objectSid",
    "distinguishedName",
    "adminCount",
    "pwdLastSet",
    "lastLogon",
    "displayName",
    "userPrincipalName",
    "servicePrincipalName",
];

pub const COMPUTER_ATTRS: &[&str] = &[
    "sAMAccountName",
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "userAccountControl",
    "objectSid",
    "distinguishedName",
    "memberOf",
    "primaryGroupID",
    "lastLogon",
];

pub const GROUP_ATTRS: &[&str] = &[
    "sAMAccountName",
    "objectSid",
    "distinguishedName",
    "member",
    "adminCount",
    "description",
];

pub const TRUST_ATTRS: &[&str] = &[
    "name",
    "trustPartner",
    "trustDirection",
    "trustType",
    "flatName",
];

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Connected (and optionally bound) LDAP client.
pub struct LdapClient {
    ldap: Ldap,
    pub bound: bool,
}

impl LdapClient {
    /// Connect to `ldap://<dc>:389`.
    pub async fn connect(dc: &str, timeout: Duration) -> Result<Self> {
        let url = format!("ldap://{}:389", dc);
        let settings = LdapConnSettings::new().set_conn_timeout(timeout);
        let (conn, ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .with_context(|| format!("LDAP connect failed: {}", url))?;
        ldap3::drive!(conn);
        Ok(LdapClient { ldap, bound: false })
    }

    /// Bind with credentials. Anonymous bind when `creds` is None.
    pub async fn bind(&mut self, creds: Option<&Credentials>, domain: &str) -> Result<()> {
        match creds {
            None => {
                self.ldap.simple_bind("", "").await.context("anonymous LDAP bind failed")?;
            }
            Some(c) => {
                let password = match &c.secret {
                    Secret::Password(p) => p.clone(),
                    // Simple bind cannot use NTLM hashes; callers must use nxc for hash auth.
                    Secret::NtlmHash(_) => bail!(
                        "LDAP simple bind does not support NTLM hash auth; use --password or nxc fallback"
                    ),
                };
                let dn = bind_dn(c, domain);
                let res = self.ldap.simple_bind(&dn, &password).await.with_context(|| {
                    format!("LDAP bind as {} failed (network)", dn)
                })?;
                res.success().map_err(|e| anyhow::anyhow!("LDAP bind as {} rejected: {}", dn, e))?;
            }
        }
        self.bound = true;
        Ok(())
    }

    /// Run a subtree search and return constructed entries.
    pub async fn search(
        &self,
        base: &str,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>> {
        // ldap3 operations need `&mut`; `Ldap` clones are cheap handles to
        // the same connection, so we keep the public API on `&self`.
        let mut ldap = self.ldap.clone();
        let (entries, _res) = ldap
            .search(base, Scope::Subtree, filter, attrs.to_vec())
            .await
            .with_context(|| format!("LDAP search failed: {}", filter))?
            .success()
            .map_err(|e| anyhow::anyhow!("LDAP search error for {}: {}", filter, e))?;
        Ok(entries.into_iter().map(SearchEntry::construct).collect())
    }

    /// Read one attribute (first value) from an entry.
    pub fn attr<'a>(entry: &'a SearchEntry, name: &str) -> Option<&'a str> {
        entry.attrs.get(name).and_then(|v| v.first()).map(String::as_str)
    }

    /// Read all values of an attribute.
    pub fn attrs<'a>(entry: &'a SearchEntry, name: &str) -> Vec<&'a str> {
        entry
            .attrs
            .get(name)
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

/// Build a bind DN: `user@domain` when possible, else the raw username.
pub fn bind_dn(creds: &Credentials, domain: &str) -> String {
    if creds.username.contains('@') || creds.username.contains('\\') {
        creds.username.clone()
    } else {
        format!("{}@{}", creds.username, domain)
    }
}

/// Convert an LDAP user entry into a raw account for parsing/classification.
pub fn entry_to_raw_account(entry: &SearchEntry) -> RawAccount {
    RawAccount {
        sam_account_name: LdapClient::attr(entry, "sAMAccountName").map(String::from),
        user_account_control: LdapClient::attr(entry, "userAccountControl")
            .and_then(|v| v.parse::<u32>().ok()),
        service_principal_names: LdapClient::attrs(entry, "servicePrincipalName")
            .iter()
            .map(|s| s.to_string())
            .collect(),
        description: LdapClient::attr(entry, "description").map(String::from),
        object_classes: LdapClient::attrs(entry, "objectClass")
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Full directory collection
// ---------------------------------------------------------------------------

/// Everything we pull out of the directory in one pass.
#[derive(Debug, Default)]
pub struct LdapData {
    pub users: Vec<SearchEntry>,
    pub groups: Vec<SearchEntry>,
    pub computers: Vec<SearchEntry>,
    pub ous: Vec<SearchEntry>,
    pub gpos: Vec<SearchEntry>,
    pub trusts: Vec<SearchEntry>,
    pub domain: Vec<SearchEntry>,
    pub base_dn: String,
}

impl LdapData {
    pub async fn collect(client: &LdapClient, base_dn: &str) -> Result<Self> {
        let mut data = LdapData { base_dn: base_dn.to_string(), ..Default::default() };
        // Users must include objectClass for account classification.
        let mut user_attrs = USER_ATTRS.to_vec();
        user_attrs.push("objectClass");
        data.users = client.search(base_dn, users_filter(), &user_attrs).await?;
        data.groups = client.search(base_dn, groups_filter(), GROUP_ATTRS).await?;
        data.computers = client.search(base_dn, computers_filter(), COMPUTER_ATTRS).await?;
        data.ous = client
            .search(base_dn, ous_filter(), &["distinguishedName", "name", "description"])
            .await?;
        data.gpos = client
            .search(base_dn, gpos_filter(), &["displayName", "gPCFileSysPath", "name"])
            .await?;
        data.trusts = client.search(base_dn, trusts_filter(), TRUST_ATTRS).await?;
        data.domain = client
            .search(base_dn, domain_filter(), &["distinguishedName", "objectSid", "name"])
            .await?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kerberoast_filter_excludes_disabled() {
        let f = kerberoastable_filter();
        assert!(f.contains("servicePrincipalName=*"));
        assert!(f.contains("1.2.840.113556.1.4.803:=2"));
    }

    #[test]
    fn asrep_filter_uses_dont_req_preauth_bit() {
        assert!(asreproastable_filter().contains(":=4194304"));
    }

    #[test]
    fn pre2k_filter_matches_uac_4128() {
        assert!(pre2k_filter().contains(":=4128"));
        assert!(pre2k_filter().contains("objectClass=computer"));
    }

    #[test]
    fn bind_dn_appends_domain() {
        let c = Credentials::with_password("alice", "x", false);
        assert_eq!(bind_dn(&c, "corp.local"), "alice@corp.local");
        let c2 = Credentials::with_password("alice@corp.local", "x", false);
        assert_eq!(bind_dn(&c2, "corp.local"), "alice@corp.local");
    }
}
