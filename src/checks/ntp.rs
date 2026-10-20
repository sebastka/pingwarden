//! SNTP (RFC 4330) query: reachability, stratum and clock offset.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;

use super::util::fmt_latency;
use super::{CheckContext, CheckResult, resolve_addr};
use crate::config::{IpVersion, NtpCheck};
use crate::model::Outcome;

/// Seconds between 1900-01-01 (NTP era 0) and 1970-01-01.
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

pub struct NtpPlan {
    host: String,
    port: u16,
    max_offset: Duration,
    max_offset_down: Option<Duration>,
    max_stratum: u8,
    ip_version: IpVersion,
}

impl NtpPlan {
    pub fn prepare(c: &NtpCheck) -> Result<Self, String> {
        if c.max_stratum == 0 || c.max_stratum > 15 {
            return Err("`max_stratum` must be between 1 and 15".into());
        }
        if let Some(d) = c.max_offset_down
            && d < c.max_offset
        {
            return Err("`max_offset_down` must not be lower than `max_offset`".into());
        }
        Ok(Self {
            host: c.host.clone(),
            port: c.port,
            max_offset: c.max_offset.0,
            max_offset_down: c.max_offset_down.map(|d| d.0),
            max_stratum: c.max_stratum,
            ip_version: c.ip_version,
        })
    }

    pub async fn run(&self, ctx: &CheckContext) -> CheckResult {
        let addr = match resolve_addr(ctx, &self.host, self.port, self.ip_version).await {
            Ok(a) => a,
            Err(e) => return CheckResult::down(e),
        };
        match self.query(addr).await {
            Ok(r) => self.evaluate(addr, r),
            Err(e) => CheckResult::down(format!("{addr}: {e}")),
        }
    }

    async fn query(&self, addr: SocketAddr) -> Result<Reply, String> {
        let bind: SocketAddr = if addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
        socket.connect(addr).await.map_err(|e| e.to_string())?;
        let mut req = [0u8; 48];
        req[0] = 0x23; // LI 0, version 4, mode 3 (client)
        let t1 = ntp_now();
        req[40..48].copy_from_slice(&t1.to_be_bytes());
        let start = Instant::now();
        socket.send(&req).await.map_err(|e| e.to_string())?;
        let mut buf = [0u8; 512];
        loop {
            let n = socket.recv(&mut buf).await.map_err(|e| match e.kind() {
                std::io::ErrorKind::ConnectionRefused => "port unreachable".to_owned(),
                _ => e.to_string(),
            })?;
            let t4 = ntp_now();
            let rtt = start.elapsed();
            if n < 48 {
                continue;
            }
            let p = &buf[..n];
            // The server copies our transmit timestamp into its originate field.
            if p[24..32] != t1.to_be_bytes() {
                continue;
            }
            let mode = p[0] & 0x7;
            if mode != 4 {
                return Err(format!("unexpected NTP mode {mode}"));
            }
            let leap = p[0] >> 6;
            let stratum = p[1];
            let t2 = u64::from_be_bytes(p[32..40].try_into().expect("8 bytes"));
            let t3 = u64::from_be_bytes(p[40..48].try_into().expect("8 bytes"));
            let offset = ((ts_diff(t2, t1) + ts_diff(t3, t4)) / 2.0) as f64;
            return Ok(Reply {
                leap,
                stratum,
                offset,
                rtt,
                kiss: (stratum == 0).then(|| String::from_utf8_lossy(&p[12..16]).trim_end_matches('\0').to_owned()),
            });
        }
    }

    fn evaluate(&self, addr: SocketAddr, r: Reply) -> CheckResult {
        if let Some(code) = r.kiss {
            return CheckResult::down(format!("{addr}: kiss-o'-death {code:?}")).with_latency(Some(r.rtt));
        }
        if r.leap == 3 {
            return CheckResult::down(format!("{addr}: server clock is not synchronized")).with_latency(Some(r.rtt));
        }
        let abs = Duration::from_secs_f64(r.offset.abs().min(1e9));
        let message = format!(
            "{addr}: stratum {}, offset {}{}, rtt {}",
            r.stratum,
            if r.offset < 0.0 { "-" } else { "+" },
            fmt_latency(abs),
            fmt_latency(r.rtt)
        );
        let mut outcome = Outcome::Up;
        if r.stratum > self.max_stratum || abs > self.max_offset {
            outcome = Outcome::Degraded;
        }
        if self.max_offset_down.is_some_and(|d| abs > d) {
            outcome = Outcome::Down;
        }
        let result = match outcome {
            Outcome::Up => CheckResult::up(Some(r.rtt), message),
            Outcome::Degraded => CheckResult::degraded(Some(r.rtt), message),
            Outcome::Down => CheckResult::down(message),
        };
        result.with_latency(Some(r.rtt))
    }
}

struct Reply {
    leap: u8,
    stratum: u8,
    /// Seconds; positive when the server is ahead of us.
    offset: f64,
    rtt: Duration,
    kiss: Option<String>,
}

fn ntp_now() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() + NTP_UNIX_OFFSET;
    let frac = (u64::from(now.subsec_nanos()) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// `a - b` in seconds, for NTP 32.32 fixed-point timestamps.
fn ts_diff(a: u64, b: u64) -> f64 {
    (a.wrapping_sub(b) as i64) as f64 / 4_294_967_296.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_difference() {
        let a = 10u64 << 32;
        let b = (9u64 << 32) | (1u64 << 31);
        assert!((ts_diff(a, b) - 0.5).abs() < 1e-9);
        assert!((ts_diff(b, a) + 0.5).abs() < 1e-9);
    }
}
