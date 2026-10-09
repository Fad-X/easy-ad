//! Native RDP reachability check.
//!
//! Performs a real X.224 Connection Request exchange (RDP negotiation) without
//! pulling in a full RDP stack. This proves the RDP service is alive and
//! speaking RDP; credential validation is left to nxc (`nxc rdp`) since a
//! CredSSP/NLA handshake is beyond a lightweight probe.

use crate::findings::{CheckStatus, Finding, Severity};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// X.224 Connection Request + RDP Negotiation Request (protocol: RDP).
fn build_x224_cr() -> Vec<u8> {
    let mut x224 = vec![
        0x03, 0x00, // TPKT: version 3, reserved
        0x00, 0x00, // TPKT length (patched below)
        0x0E, // LI: fixed(6) + RDP negotiation(8)
        0xE0, // CR: connection request code
        0x00, 0x00, // dst-ref
        0x00, 0x01, // src-ref
        0x00, // class 0
        // RDP Negotiation Request
        0x01, // type
        0x00, // flags
        0x08, 0x00, // length
        0x00, 0x00, 0x00, 0x00, // requested protocols: RDP
    ];
    let total = x224.len() as u16;
    x224[2] = (total >> 8) as u8;
    x224[3] = (total & 0xff) as u8;
    x224
}

/// Possible outcomes of the RDP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpProbe {
    /// X.224 Connection Confirm received - RDP service is up.
    Reachable,
    /// TCP connected but no valid RDP response - not (only) RDP.
    NotRdp,
    /// Connection refused / timed out.
    Unreachable,
}

/// Probe RDP on `host:3389` and return a finding.
pub async fn check(host: &str, timeout_secs: u64) -> Finding {
    match probe(host, timeout_secs).await {
        RdpProbe::Reachable => Finding::new(
            host,
            "rdp",
            "access",
            CheckStatus::Success,
            Severity::Info,
            serde_json::json!({ "message": "RDP service reachable (X.224 connection confirm received)" }),
        ),
        RdpProbe::NotRdp => Finding::new(host, "rdp", "access", CheckStatus::Error, Severity::Info, serde_json::json!({ "message": "port 3389 open but not speaking RDP" })),
        RdpProbe::Unreachable => Finding::new(host, "rdp", "access", CheckStatus::Unreachable, Severity::Info, serde_json::json!({ "message": "no response" })),
    }
}

/// Probe RDP: TCP connect to 3389, send X.224 CR, expect X.224 CC (0xD0).
pub async fn probe(host: &str, timeout_secs: u64) -> RdpProbe {
    let fut = timeout(Duration::from_secs(timeout_secs), async {
        let mut stream = TcpStream::connect((host, 3389)).await?;
        stream.write_all(&build_x224_cr()).await?;
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        Ok::<_, std::io::Error>((n, buf))
    });
    match fut.await {
        Ok(Ok((n, buf))) if n >= 4 => {
            let is_x224_cc = buf[0] == 3 && n > 5 && buf[5] & 0xF0 == 0xD0;
            if is_x224_cc {
                RdpProbe::Reachable
            } else {
                RdpProbe::NotRdp
            }
        }
        Ok(Ok(_)) => RdpProbe::NotRdp,
        Ok(Err(_)) => RdpProbe::Unreachable,
        Err(_) => RdpProbe::Unreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x224_cr_is_wellformed_tpkt() {
        let pkt = build_x224_cr();
        assert_eq!(pkt[0], 3); // TPKT version
        let len = ((pkt[2] as usize) << 8) | pkt[3] as usize;
        assert_eq!(len, pkt.len());
        assert_eq!(pkt[4], 0x0E); // LI
        assert_eq!(pkt[5], 0xE0); // CR code
        assert_eq!(pkt[pkt.len() - 4..], [0x00, 0x00, 0x00, 0x00]); // proto RDP
    }
}
