//! UDP probe. UDP has no handshake: a reply proves the service is alive, an
//! ICMP port-unreachable (`ECONNREFUSED` on a connected socket) proves it is
//! not, and silence proves nothing.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use regex::bytes::Regex;
use tokio::net::UdpSocket;

use super::util::{bytes_option, contains_bytes, excerpt, fmt_latency};
use super::{CheckContext, CheckResult, resolve_addr};
use crate::config::{IpVersion, UdpCheck};

pub struct UdpPlan {
    host: String,
    port: u16,
    payload: Vec<u8>,
    expect: Option<Vec<u8>>,
    expect_regex: Option<Regex>,
    expect_response: bool,
    ip_version: IpVersion,
}

impl UdpPlan {
    pub fn prepare(c: &UdpCheck) -> Result<Self, String> {
        if c.port == 0 {
            return Err("`port` must not be 0".into());
        }
        let payload = bytes_option(&c.payload, &c.payload_hex, "payload")?.unwrap_or_default();
        let expect = bytes_option(&c.expect, &c.expect_hex, "expect")?;
        let expect_regex = c
            .expect_regex
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|e| format!("expect_regex: {e}"))?;
        Ok(Self {
            host: c.host.clone(),
            port: c.port,
            payload,
            expect,
            expect_regex,
            expect_response: c.expect_response,
            ip_version: c.ip_version,
        })
    }

    pub async fn run(&self, ctx: &CheckContext) -> CheckResult {
        let addr = match resolve_addr(ctx, &self.host, self.port, self.ip_version).await {
            Ok(a) => a,
            Err(e) => return CheckResult::down(e),
        };
        let bind: SocketAddr = if addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = match UdpSocket::bind(bind).await {
            Ok(s) => s,
            Err(e) => return CheckResult::down(format!("cannot bind UDP socket: {e}")),
        };
        if let Err(e) = socket.connect(addr).await {
            return CheckResult::down(format!("{addr}: {e}"));
        }
        let start = Instant::now();
        if let Err(e) = socket.send(&self.payload).await {
            return CheckResult::down(format!("{addr}: send failed: {e}"));
        }
        let mut buf = vec![0u8; 65_536];
        // The caller's timeout bounds this wait. Without an expected response
        // we only listen for a short while for an ICMP error.
        let wait = async {
            loop {
                match socket.recv(&mut buf).await {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
        };
        let received = if self.expect_response {
            Some(wait.await)
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(2), wait).await.ok()
        };
        let rtt = start.elapsed();
        match received {
            None => CheckResult::up(None, format!("{addr}: no reply and no ICMP error (open or filtered)")),
            Some(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => {
                CheckResult::down(format!("{addr}: port unreachable"))
            }
            Some(Err(e)) => CheckResult::down(format!("{addr}: {e}")),
            Some(Ok(n)) => {
                let data = &buf[..n];
                let ok = self.expect.as_deref().is_none_or(|e| contains_bytes(data, e))
                    && self.expect_regex.as_ref().is_none_or(|r| r.is_match(data));
                if ok {
                    CheckResult::up(Some(rtt), format!("{addr}: {n} bytes in {}", fmt_latency(rtt)))
                } else {
                    CheckResult::down(format!("{addr}: unexpected reply {:?}", excerpt(data))).with_latency(Some(rtt))
                }
            }
        }
    }
}
