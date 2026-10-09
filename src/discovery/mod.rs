//! IP / subnet scanning (CIDR expansion) and Domain Controller discovery.

pub mod parser;

use anyhow::{Context, Result};
use hickory_resolver::TokioResolver;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Build a system-configured async DNS resolver.
fn resolver() -> Result<TokioResolver> {
    TokioResolver::builder_tokio()
        .context("cannot build DNS resolver")?
        .build()
        .context("cannot build DNS resolver")
}

/// Hard cap on the number of hosts we will expand a target specification into.
const MAX_EXPANDED_HOSTS: usize = 4096;

/// Ports probed per host during discovery.
pub const AD_PORTS: &[u16] = &[445, 139, 389, 636, 3268, 3389, 5985, 5986, 1433, 88];

/// A discovered host and its open AD-relevant ports.
#[derive(Debug, Clone)]
pub struct Host {
    pub ip: IpAddr,
    pub open_ports: Vec<u16>,
}

impl Host {
    pub fn is_up(&self) -> bool {
        !self.open_ports.is_empty()
    }
}

/// Expand a `--target` specification into a deduplicated list of IPs.
///
/// Accepts: single IPs, hostnames (resolved), comma-separated lists, and
/// CIDR subnets (e.g. `192.168.1.0/24`).
pub async fn expand_targets(spec: &str) -> Result<Vec<IpAddr>> {
    let mut out: Vec<IpAddr> = Vec::new();
    for token in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(ip) = token.parse::<IpAddr>() {
            out.push(ip);
            continue;
        }
        if let Ok(net) = token.parse::<ipnet::IpNet>() {
            let hosts: Vec<IpAddr> = net.hosts().collect();
            if out.len() + hosts.len() > MAX_EXPANDED_HOSTS {
                anyhow::bail!(
                    "target {} expands to more than {} hosts; narrow the CIDR range",
                    token,
                    MAX_EXPANDED_HOSTS
                );
            }
            out.extend(hosts);
            continue;
        }
        // Treat as hostname; resolve via system DNS.
        let lookup = resolver()?
            .lookup_ip(token)
            .await
            .with_context(|| format!("cannot resolve hostname '{}'", token))?;
        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            anyhow::bail!("hostname '{}' resolved to no addresses", token);
        }
        out.extend(ips);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// TCP-connect probe of one host across [`AD_PORTS`].
pub async fn probe_host(ip: IpAddr, timeout_secs: u64) -> Host {
    let mut open = Vec::new();
    for &port in AD_PORTS {
        let addr = SocketAddr::new(ip, port);
        let fut = timeout(Duration::from_secs(timeout_secs), TcpStream::connect(addr));
        if let Ok(Ok(_)) = fut.await {
            open.push(port);
        }
    }
    Host { ip, open_ports: open }
}

/// Concurrently probe a list of hosts, bounded by `threads`.
pub async fn probe_hosts(ips: Vec<IpAddr>, threads: usize, timeout_secs: u64) -> Vec<Host> {
    let sem = std::sync::Arc::new(Semaphore::new(threads.max(1)));
    let mut tasks = Vec::new();
    for ip in ips {
        let sem = sem.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            probe_host(ip, timeout_secs).await
        }));
    }
    let mut hosts = Vec::new();
    for t in tasks {
        match t.await {
            Ok(h) => hosts.push(h),
            Err(e) => tracing::warn!("probe task failed: {}", e),
        }
    }
    hosts.sort_by_key(|h| h.ip);
    hosts
}

/// Auto-discover a Domain Controller for `domain` via DNS SRV records
/// (`_ldap._tcp.dc._msdcs.<domain>`). Returns the first DC IP.
pub async fn discover_dc(domain: &str) -> Result<String> {
    let resolver = resolver()?;
    let srv_name = format!("_ldap._tcp.dc._msdcs.{}", domain);
    let lookup = resolver
        .srv_lookup(srv_name.clone())
        .await
        .with_context(|| {
            format!(
                "DNS SRV lookup failed for {} - specify the DC explicitly with --dc",
                srv_name
            )
        })?;
    for record in lookup.answers() {
        use hickory_resolver::proto::rr::RData;
        if let RData::SRV(srv) = &record.data {
            let target = srv.target.to_string();
            if let Ok(ips) = resolver.lookup_ip(target.trim_end_matches('.')).await {
                if let Some(ip) = ips.iter().next() {
                    return Ok(ip.to_string());
                }
            }
        }
    }
    anyhow::bail!("no SRV records for {} resolved to an address", srv_name)
}

/// Derive a best-effort base DN from a DNS domain name: `corp.local` -> `DC=corp,DC=local`.
pub fn domain_to_base_dn(domain: &str) -> String {
    domain
        .trim_end_matches('.')
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| format!("DC={}", s))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn expands_single_ip() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ips = rt.block_on(expand_targets("10.0.0.5")).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]);
    }

    #[test]
    fn expands_comma_separated() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ips = rt.block_on(expand_targets("10.0.0.1,10.0.0.2 , 10.0.0.1")).unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn expands_cidr_and_dedupes() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ips = rt.block_on(expand_targets("192.168.1.0/30,192.168.1.2")).unwrap();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            ]
        );
    }

    #[test]
    fn rejects_oversized_cidr() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(rt.block_on(expand_targets("10.0.0.0/8")).is_err());
    }

    #[test]
    fn builds_base_dn() {
        assert_eq!(domain_to_base_dn("corp.local"), "DC=corp,DC=local");
        assert_eq!(domain_to_base_dn("CORP.LOCAL."), "DC=CORP,DC=LOCAL");
    }
}
