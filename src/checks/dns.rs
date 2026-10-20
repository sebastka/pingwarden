//! DNS query against the system resolvers or a given server, without cache.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;

use super::util::fmt_latency;
use super::{CheckContext, CheckResult};
use crate::config::{DnsCheck, DnsProtocol, ExpectMode};

pub struct DnsPlan {
    name: String,
    record_type: RecordType,
    server: Option<SocketAddr>,
    protocol: DnsProtocol,
    expect: BTreeSet<String>,
    mode: ExpectMode,
    resolver: OnceLock<Result<TokioResolver, String>>,
}

impl DnsPlan {
    pub fn prepare(c: &DnsCheck) -> Result<Self, String> {
        let record_type = RecordType::from_str(&c.record_type.to_ascii_uppercase())
            .map_err(|_| format!("unknown record_type {:?}", c.record_type))?;
        let server = c.server.as_deref().map(parse_server).transpose()?;
        if c.expect.is_empty() && c.expect_mode == ExpectMode::Exact {
            return Err("`expect_mode: exact` requires `expect`".into());
        }
        Ok(Self {
            name: c.domain.clone(),
            record_type,
            server,
            protocol: c.protocol,
            expect: c.expect.iter().map(|e| normalize(e)).collect(),
            mode: c.expect_mode,
            resolver: OnceLock::new(),
        })
    }

    fn resolver(&self, timeout: Duration) -> Result<&TokioResolver, String> {
        self.resolver
            .get_or_init(|| {
                let conn = |port: u16| {
                    let mut c = match self.protocol {
                        DnsProtocol::Udp => ConnectionConfig::udp(),
                        DnsProtocol::Tcp => ConnectionConfig::tcp(),
                    };
                    c.port = port;
                    c
                };
                let (config, mut opts) = match self.server {
                    Some(addr) => (
                        ResolverConfig::from_name_servers(vec![NameServerConfig::new(
                            addr.ip(),
                            true,
                            vec![conn(addr.port())],
                        )]),
                        ResolverOpts::default(),
                    ),
                    None => {
                        let (system, opts) = hickory_resolver::system_conf::read_system_conf()
                            .map_err(|e| format!("cannot read system resolver configuration: {e}"))?;
                        let servers = system
                            .name_servers()
                            .iter()
                            .map(|ns| NameServerConfig::new(ns.ip, true, vec![conn(53)]))
                            .collect();
                        (ResolverConfig::from_name_servers(servers), opts)
                    }
                };
                // Every check must reach the server; never answer from cache.
                opts.cache_size = 0;
                opts.attempts = 1;
                opts.timeout = timeout;
                let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
                *builder.options_mut() = opts;
                builder.build().map_err(|e| format!("cannot build resolver: {e}"))
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    pub async fn run(&self, _ctx: &CheckContext, timeout: Duration) -> CheckResult {
        let resolver = match self.resolver(timeout) {
            Ok(r) => r,
            Err(e) => return CheckResult::down(e),
        };
        let start = Instant::now();
        let lookup = match resolver.lookup(self.name.as_str(), self.record_type).await {
            Ok(l) => l,
            Err(e) => return CheckResult::down(format!("{} {}: {e}", self.name, self.record_type)),
        };
        let latency = start.elapsed();
        let answers: BTreeSet<String> = lookup
            .answers()
            .iter()
            .filter(|r| r.record_type() == self.record_type)
            .map(|r| normalize(&r.data.to_string()))
            .collect();
        let shown = answers.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
        if answers.is_empty() {
            return CheckResult::down(format!("{} {}: no record", self.name, self.record_type))
                .with_latency(Some(latency));
        }
        let ok = match self.mode {
            ExpectMode::Contains => self.expect.is_subset(&answers),
            ExpectMode::Exact => self.expect == answers,
        };
        if ok {
            CheckResult::up(
                Some(latency),
                format!(
                    "{} {} = {shown} in {}",
                    self.name,
                    self.record_type,
                    fmt_latency(latency)
                ),
            )
        } else {
            let missing: Vec<_> = self.expect.difference(&answers).cloned().collect();
            let detail = if missing.is_empty() {
                format!("unexpected extra records, got {shown}")
            } else {
                format!("missing {}, got {shown}", missing.join(", "))
            };
            CheckResult::down(format!("{} {}: {detail}", self.name, self.record_type)).with_latency(Some(latency))
        }
    }
}

fn parse_server(s: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    s.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .map_err(|_| format!("invalid DNS server {s:?}, expected an IP address with optional port"))
}

/// Compare records case-insensitively, without trailing dots or quotes.
fn normalize(s: &str) -> String {
    s.trim().trim_matches('"').trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_servers() {
        assert_eq!(parse_server("1.1.1.1").unwrap(), "1.1.1.1:53".parse().unwrap());
        assert_eq!(parse_server("1.1.1.1:5353").unwrap(), "1.1.1.1:5353".parse().unwrap());
        assert_eq!(parse_server("[::1]:53").unwrap(), "[::1]:53".parse().unwrap());
        assert_eq!(parse_server("::1").unwrap(), "[::1]:53".parse().unwrap());
        assert!(parse_server("dns.google").is_err());
    }

    #[test]
    fn normalizes() {
        assert_eq!(normalize("Mail.Example.com."), "mail.example.com");
        assert_eq!(normalize("\"v=spf1 -all\""), "v=spf1 -all");
    }
}
