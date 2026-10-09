//! Integration tests against a live (mock) AD environment.
//!
//! These tests are **ignored by default**. To run them, bring up a Samba AD DC
//! (or any test domain) and set the environment variables below, then:
//!
//! ```bash
//! cargo test --test integration -- --include-ignored
//! ```
//!
//! Quick mock environment with Docker:
//!
//! ```bash
//! docker run --rm -d --name samba-dc -p 389:389 -p 445:445 -p 636:636 \
//!   -e REALM=EXAMPLE.TEST -e DOMAIN=EXAMPLE -e ADMIN_PASS=Passw0rd! \
//!   bbusse/samba-ad-dc
//! ```

use easy_ad::discovery::{domain_to_base_dn, expand_targets};
use easy_ad::scanner::ldap::{self, LdapClient};
use std::net::IpAddr;

fn dc() -> String {
    std::env::var("EASY_AD_TEST_DC").expect("set EASY_AD_TEST_DC to a reachable DC")
}

fn domain() -> String {
    std::env::var("EASY_AD_TEST_DOMAIN").unwrap_or_else(|_| "example.test".to_string())
}

fn creds() -> easy_ad::auth::Credentials {
    let user = std::env::var("EASY_AD_TEST_USER").unwrap_or_else(|_| "administrator".to_string());
    let pass = std::env::var("EASY_AD_TEST_PASS").expect("set EASY_AD_TEST_PASS");
    easy_ad::auth::Credentials::with_password(user, pass, false)
}

#[tokio::test]
#[ignore = "requires a live AD environment (see module docs)"]
async fn ldap_bind_and_collect() {
    let mut client = LdapClient::connect(&dc(), std::time::Duration::from_secs(10))
        .await
        .expect("connect");
    client
        .bind(Some(&creds()), &domain())
        .await
        .expect("bind");

    let base = domain_to_base_dn(&domain());
    let data = ldap::LdapData::collect(&client, &base).await.expect("collect");
    assert!(!data.users.is_empty(), "expected users in the directory");
    assert!(!data.groups.is_empty(), "expected groups in the directory");
}

#[tokio::test]
#[ignore = "requires a live AD environment (see module docs)"]
async fn kerberoast_filter_is_valid_ldap() {
    let mut client = LdapClient::connect(&dc(), std::time::Duration::from_secs(10))
        .await
        .expect("connect");
    client
        .bind(Some(&creds()), &domain())
        .await
        .expect("bind");
    let base = domain_to_base_dn(&domain());
    // Must not error - filter syntax is valid for the server.
    let _ = client
        .search(&base, ldap::kerberoastable_filter(), ldap::USER_ATTRS)
        .await
        .expect("kerberoastable filter search");
    let _ = client
        .search(&base, ldap::asreproastable_filter(), ldap::USER_ATTRS)
        .await
        .expect("asreproastable filter search");
}

#[test]
fn cidr_expansion_is_stable() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ips = rt.block_on(expand_targets("10.10.10.0/30")).unwrap();
    assert_eq!(ips.len(), 2);
    assert_eq!(ips[0], "10.10.10.1".parse::<IpAddr>().unwrap());
}
