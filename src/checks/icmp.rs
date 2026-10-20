//! ICMP echo. One shared socket per address family; datagram ICMP sockets are
//! tried first (no capability needed when `net.ipv4.ping_group_range` allows
//! it), raw sockets (`CAP_NET_RAW`) second.

use std::net::IpAddr;
use std::time::Duration;

use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence, SurgeError};
use tokio::sync::OnceCell;

use super::{CheckContext, CheckResult, resolve_ip, util::fmt_latency};
use crate::config::{IcmpCheck, IpVersion};

#[derive(Default)]
pub struct IcmpClients {
    v4: OnceCell<Result<Client, String>>,
    v6: OnceCell<Result<Client, String>>,
}

impl IcmpClients {
    async fn get(&self, ip: IpAddr) -> Result<&Client, String> {
        let (cell, kind) = match ip {
            IpAddr::V4(_) => (&self.v4, ICMP::V4),
            IpAddr::V6(_) => (&self.v6, ICMP::V6),
        };
        let client = cell
            .get_or_init(|| async move {
                let config = Config::builder().kind(kind).build();
                Client::new(&config).map_err(|e| {
                    let msg =
                        format!("cannot open ICMP socket: {e} (grant CAP_NET_RAW or widen net.ipv4.ping_group_range)");
                    tracing::error!("{msg}");
                    msg
                })
            })
            .await;
        client.as_ref().map_err(Clone::clone)
    }
}

pub struct IcmpPlan {
    host: String,
    count: u16,
    payload: Vec<u8>,
    packet_timeout: Duration,
    ip_version: IpVersion,
    down_loss: f64,
    degraded_loss: Option<f64>,
}

impl IcmpPlan {
    pub fn prepare(c: &IcmpCheck) -> Result<Self, String> {
        if c.count == 0 || c.count > 100 {
            return Err("`count` must be between 1 and 100".into());
        }
        if c.packet_size > 65_000 {
            return Err("`packet_size` must be at most 65000".into());
        }
        for (name, v) in [
            ("down_loss_percent", Some(c.down_loss_percent)),
            ("degraded_loss_percent", c.degraded_loss_percent),
        ] {
            if let Some(v) = v
                && !(0.0..=100.0).contains(&v)
            {
                return Err(format!("`{name}` must be between 0 and 100"));
            }
        }
        if c.packet_timeout.is_zero() {
            return Err("`packet_timeout` must be positive".into());
        }
        Ok(Self {
            host: c.host.clone(),
            count: c.count as u16,
            payload: vec![0; c.packet_size],
            packet_timeout: c.packet_timeout.0,
            ip_version: c.ip_version,
            down_loss: c.down_loss_percent,
            degraded_loss: c.degraded_loss_percent,
        })
    }

    pub async fn run(&self, ctx: &CheckContext) -> CheckResult {
        let ip = match resolve_ip(ctx, &self.host, self.ip_version).await {
            Ok(ip) => ip,
            Err(e) => return CheckResult::down(e),
        };
        let client = match ctx.icmp.get(ip).await {
            Ok(c) => c,
            Err(e) => return CheckResult::down(e),
        };
        let mut pinger = client.pinger(ip, PingIdentifier(rand::random())).await;
        pinger.timeout(self.packet_timeout);
        let mut rtts = Vec::with_capacity(self.count as usize);
        let mut last_error = None;
        for seq in 0..self.count {
            match pinger.ping(PingSequence(seq), &self.payload).await {
                Ok((_, rtt)) => rtts.push(rtt),
                Err(SurgeError::Timeout { .. }) => {}
                Err(e) => last_error = Some(e.to_string()),
            }
            if seq + 1 < self.count {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        let received = rtts.len();
        let loss = 100.0 * (1.0 - received as f64 / self.count as f64);
        if received == 0 {
            let reason = last_error.unwrap_or_else(|| "no reply".into());
            return CheckResult::down(format!("{ip}: 0/{} replies ({reason})", self.count));
        }
        let avg = rtts.iter().sum::<Duration>() / received as u32;
        let max = rtts.iter().max().copied().unwrap_or_default();
        let message = format!(
            "{ip}: {received}/{} replies, avg {}, max {}, loss {loss:.0}%",
            self.count,
            fmt_latency(avg),
            fmt_latency(max)
        );
        if loss >= self.down_loss {
            CheckResult::down(message).with_latency(Some(avg))
        } else if self.degraded_loss.is_some_and(|d| loss >= d) {
            CheckResult::degraded(Some(avg), message)
        } else {
            CheckResult::up(Some(avg), message)
        }
    }
}
