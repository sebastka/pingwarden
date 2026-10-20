//! Check implementations. Each check is prepared once from its configuration
//! (validating and compiling everything that can be) and then executed on
//! every tick with a shared [`CheckContext`].

mod database;
mod dns;
mod http;
mod icmp;
mod ntp;
mod tcp;
mod tls;
mod udp;
pub mod util;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;

use crate::config::{CheckConfig, IpVersion, TlsConfig};
use crate::model::Outcome;

/// What a check reports.
#[derive(Clone, Debug)]
pub struct CheckResult {
    pub outcome: Outcome,
    pub latency: Option<Duration>,
    pub message: String,
    /// Earliest certificate expiry seen (unix seconds), for TLS-based checks.
    pub cert_expiry: Option<i64>,
}

impl CheckResult {
    pub fn up(latency: Option<Duration>, message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Up,
            latency,
            message: message.into(),
            cert_expiry: None,
        }
    }

    pub fn degraded(latency: Option<Duration>, message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Degraded,
            latency,
            message: message.into(),
            cert_expiry: None,
        }
    }

    pub fn down(message: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Down,
            latency: None,
            message: message.into(),
            cert_expiry: None,
        }
    }

    pub fn with_latency(mut self, latency: Option<Duration>) -> Self {
        self.latency = latency;
        self
    }
}

/// Resources shared by every check.
pub struct CheckContext {
    pub resolver: TokioResolver,
    pub roots: Arc<RootCertStore>,
    /// The configured extra CAs, also handed to the HTTP client.
    pub extra_roots: Vec<CertificateDer<'static>>,
    pub icmp: icmp::IcmpClients,
}

impl CheckContext {
    pub fn new(tls: &TlsConfig) -> anyhow::Result<Self> {
        let resolver = util::system_resolver()?;
        let (roots, extra_roots) = util::load_roots(tls)?;
        Ok(Self {
            resolver,
            roots: Arc::new(roots),
            extra_roots,
            icmp: icmp::IcmpClients::default(),
        })
    }
}

/// A prepared check.
pub enum Check {
    Icmp(icmp::IcmpPlan),
    Tcp(tcp::TcpPlan),
    Udp(udp::UdpPlan),
    Http(Box<http::HttpPlan>),
    Tls(tls::TlsPlan),
    Dns(Box<dns::DnsPlan>),
    Ntp(ntp::NtpPlan),
    Database(database::DatabasePlan),
    /// Passive: results arrive through the push API.
    Push,
}

impl Check {
    /// Validate and compile a check configuration. Must not do any I/O.
    pub fn prepare(cfg: &CheckConfig) -> Result<Self, String> {
        Ok(match cfg {
            CheckConfig::Icmp(c) => Check::Icmp(icmp::IcmpPlan::prepare(c)?),
            CheckConfig::Tcp(c) => Check::Tcp(tcp::TcpPlan::prepare(c)?),
            CheckConfig::Udp(c) => Check::Udp(udp::UdpPlan::prepare(c)?),
            CheckConfig::Http(c) => Check::Http(Box::new(http::HttpPlan::prepare(c)?)),
            CheckConfig::Tls(c) => Check::Tls(tls::TlsPlan::prepare(c)?),
            CheckConfig::Dns(c) => Check::Dns(Box::new(dns::DnsPlan::prepare(c)?)),
            CheckConfig::Ntp(c) => Check::Ntp(ntp::NtpPlan::prepare(c)?),
            CheckConfig::Postgres(c) => {
                Check::Database(database::DatabasePlan::prepare(c, database::Engine::Postgres)?)
            }
            CheckConfig::Mysql(c) => Check::Database(database::DatabasePlan::prepare(c, database::Engine::Mysql)?),
            CheckConfig::Push(_) => Check::Push,
        })
    }

    pub fn is_passive(&self) -> bool {
        matches!(self, Check::Push)
    }

    /// Run the check once, bounded by `timeout`.
    pub async fn run(&self, ctx: &CheckContext, timeout: Duration) -> CheckResult {
        let fut = async {
            match self {
                Check::Icmp(p) => p.run(ctx).await,
                Check::Tcp(p) => p.run(ctx).await,
                Check::Udp(p) => p.run(ctx).await,
                Check::Http(p) => p.run(ctx).await,
                Check::Tls(p) => p.run(ctx).await,
                Check::Dns(p) => p.run(ctx, timeout).await,
                Check::Ntp(p) => p.run(ctx).await,
                Check::Database(p) => p.run().await,
                Check::Push => CheckResult::down("push monitors are not executed"),
            }
        };
        match tokio::time::timeout(timeout, fut).await {
            Ok(r) => r,
            Err(_) => CheckResult::down(format!("timed out after {}", crate::config::Dur(timeout))),
        }
    }
}

/// Resolve `host` to one address of the requested family.
pub async fn resolve_ip(ctx: &CheckContext, host: &str, version: IpVersion) -> Result<IpAddr, String> {
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return match (version, ip) {
            (IpVersion::V4, IpAddr::V6(_)) | (IpVersion::V6, IpAddr::V4(_)) => {
                Err(format!("{ip} does not match ip_version"))
            }
            _ => Ok(ip),
        };
    }
    let lookup = ctx
        .resolver
        .lookup_ip(host)
        .await
        .map_err(|e| format!("cannot resolve {host}: {e}"))?;
    // `any` prefers IPv4: many container networks have no IPv6 route, and
    // `ip_version: 6` exists to monitor IPv6 explicitly.
    let mut v4 = lookup.iter().filter(IpAddr::is_ipv4);
    let mut v6 = lookup.iter().filter(IpAddr::is_ipv6);
    match version {
        IpVersion::Any => v4.next().or_else(|| v6.next()),
        IpVersion::V4 => v4.next(),
        IpVersion::V6 => v6.next(),
    }
    .ok_or_else(|| format!("{host} has no address matching ip_version"))
}

pub async fn resolve_addr(ctx: &CheckContext, host: &str, port: u16, version: IpVersion) -> Result<SocketAddr, String> {
    resolve_ip(ctx, host, version).await.map(|ip| SocketAddr::new(ip, port))
}
