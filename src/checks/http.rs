//! HTTP(S) request with status, keyword and JSON matching.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use hickory_resolver::TokioResolver;
use regex::Regex;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, redirect};
use serde_json::Value;

use super::util::fmt_latency;
use super::{CheckContext, CheckResult};
use crate::config::{HttpCheck, IpVersion};

pub struct HttpPlan {
    url: reqwest::Url,
    method: Method,
    headers: HeaderMap,
    body: Option<String>,
    accepted: Vec<(u16, u16)>,
    keyword: Option<String>,
    keyword_regex: Option<Regex>,
    invert_keyword: bool,
    json: Option<(Vec<String>, Option<Value>)>,
    redirect: Option<usize>,
    tls_verify: bool,
    basic_auth: Option<(String, String)>,
    bearer: Option<String>,
    max_body: usize,
    ip_version: IpVersion,
    client: OnceLock<Result<reqwest::Client, String>>,
}

impl HttpPlan {
    pub fn prepare(c: &HttpCheck) -> Result<Self, String> {
        let url = reqwest::Url::parse(&c.url).map_err(|e| format!("invalid url: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err("url scheme must be http or https".into());
        }
        let method = Method::from_bytes(c.method.to_ascii_uppercase().as_bytes())
            .map_err(|_| format!("invalid method {:?}", c.method))?;
        let mut headers = HeaderMap::new();
        for (k, v) in &c.headers {
            let name = HeaderName::from_bytes(k.as_bytes()).map_err(|_| format!("invalid header name {k:?}"))?;
            let value = HeaderValue::from_str(v).map_err(|_| format!("invalid value for header {k:?}"))?;
            headers.append(name, value);
        }
        let accepted = c
            .accepted_status
            .iter()
            .map(|s| parse_status_range(s))
            .collect::<Result<Vec<_>, _>>()?;
        if accepted.is_empty() {
            return Err("`accepted_status` must not be empty".into());
        }
        let keyword_regex = c
            .keyword_regex
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|e| format!("keyword_regex: {e}"))?;
        if c.keyword.is_some() && keyword_regex.is_some() {
            return Err("set only one of `keyword` and `keyword_regex`".into());
        }
        if c.invert_keyword && c.keyword.is_none() && keyword_regex.is_none() {
            return Err("`invert_keyword` requires `keyword` or `keyword_regex`".into());
        }
        let json = match (&c.json_path, &c.json_value) {
            (Some(p), v) => Some((p.split('.').map(str::to_owned).collect(), v.clone())),
            (None, Some(_)) => return Err("`json_value` requires `json_path`".into()),
            (None, None) => None,
        };
        if c.basic_auth.is_some() && c.bearer_token.is_some() {
            return Err("set only one of `basic_auth` and `bearer_token`".into());
        }
        Ok(Self {
            url,
            method,
            headers,
            body: c.body.clone(),
            accepted,
            keyword: c.keyword.clone(),
            keyword_regex,
            invert_keyword: c.invert_keyword,
            json,
            redirect: c.follow_redirects.then_some(c.max_redirects),
            tls_verify: c.tls_verify,
            basic_auth: c.basic_auth.as_ref().map(|b| (b.username.clone(), b.password.clone())),
            bearer: c.bearer_token.clone(),
            max_body: c.max_body_size,
            ip_version: c.ip_version,
            client: OnceLock::new(),
        })
    }

    fn client(&self, ctx: &CheckContext) -> Result<&reqwest::Client, String> {
        self.client
            .get_or_init(|| {
                let mut b = reqwest::Client::builder()
                    .user_agent(concat!("Pingwarden/", env!("CARGO_PKG_VERSION")))
                    // Fresh connection on every check: measures the real
                    // handshake and keeps no idle sockets in memory.
                    .pool_max_idle_per_host(0)
                    .redirect(match self.redirect {
                        Some(n) => redirect::Policy::limited(n),
                        None => redirect::Policy::none(),
                    })
                    .dns_resolver(Arc::new(HickoryResolve {
                        resolver: ctx.resolver.clone(),
                        version: self.ip_version,
                    }));
                if !self.tls_verify {
                    b = b.tls_danger_accept_invalid_certs(true);
                }
                if !ctx.extra_roots.is_empty() {
                    let certs = ctx
                        .extra_roots
                        .iter()
                        .filter_map(|c| reqwest::Certificate::from_der(c).ok())
                        .collect::<Vec<_>>();
                    b = b.tls_certs_merge(certs);
                }
                b.build().map_err(|e| format!("cannot build HTTP client: {e}"))
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    pub async fn run(&self, ctx: &CheckContext) -> CheckResult {
        let client = match self.client(ctx) {
            Ok(c) => c,
            Err(e) => return CheckResult::down(e),
        };
        let mut req = client
            .request(self.method.clone(), self.url.clone())
            .headers(self.headers.clone());
        if let Some(body) = &self.body {
            req = req.body(body.clone());
        }
        if let Some((u, p)) = &self.basic_auth {
            req = req.basic_auth(u, Some(p));
        }
        if let Some(t) = &self.bearer {
            req = req.bearer_auth(t);
        }
        let start = Instant::now();
        let mut resp = match req.send().await {
            Ok(r) => r,
            Err(e) => return CheckResult::down(describe_error(&e)),
        };
        let status = resp.status().as_u16();
        let needs_body = self.keyword.is_some() || self.keyword_regex.is_some() || self.json.is_some();
        let mut body = Vec::new();
        if needs_body {
            loop {
                match resp.chunk().await {
                    Ok(Some(chunk)) => {
                        let room = self.max_body.saturating_sub(body.len());
                        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
                        if body.len() >= self.max_body {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => return CheckResult::down(format!("error reading body: {}", describe_error(&e))),
                }
            }
        }
        let latency = start.elapsed();
        let lat = Some(latency);
        if !self.accepted.iter().any(|(lo, hi)| (*lo..=*hi).contains(&status)) {
            return CheckResult::down(format!("HTTP {status} is not accepted")).with_latency(lat);
        }
        let text = String::from_utf8_lossy(&body);
        if let Some(found) = self.keyword_found(&text) {
            let wanted = !self.invert_keyword;
            if found != wanted {
                let what = if found { "found" } else { "not found" };
                return CheckResult::down(format!("HTTP {status}, keyword {what}")).with_latency(lat);
            }
        }
        if let Some((path, expected)) = &self.json {
            let value: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => return CheckResult::down(format!("HTTP {status}, invalid JSON: {e}")).with_latency(lat),
            };
            let Some(actual) = json_lookup(&value, path) else {
                return CheckResult::down(format!("HTTP {status}, JSON path {} not found", path.join(".")))
                    .with_latency(lat);
            };
            if let Some(expected) = expected
                && !json_matches(actual, expected)
            {
                return CheckResult::down(format!(
                    "HTTP {status}, {} is {actual}, expected {expected}",
                    path.join(".")
                ))
                .with_latency(lat);
            }
        }
        CheckResult::up(lat, format!("HTTP {status} in {}", fmt_latency(latency)))
    }

    fn keyword_found(&self, text: &str) -> Option<bool> {
        if let Some(k) = &self.keyword {
            return Some(text.contains(k.as_str()));
        }
        self.keyword_regex.as_ref().map(|r| r.is_match(text))
    }
}

fn describe_error(e: &reqwest::Error) -> String {
    // reqwest's Display hides the cause; walk the chain for a useful message.
    let mut msg = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        source = s.source();
    }
    msg
}

pub fn parse_status_range(s: &str) -> Result<(u16, u16), String> {
    let err = || format!("invalid status {s:?}, expected e.g. 200, 200-299 or 2xx");
    let s = s.trim();
    if let Some(prefix) = s.strip_suffix("xx") {
        let d: u16 = prefix.parse().map_err(|_| err())?;
        if !(1..=5).contains(&d) {
            return Err(err());
        }
        return Ok((d * 100, d * 100 + 99));
    }
    let (lo, hi) = match s.split_once('-') {
        Some((a, b)) => (
            a.trim().parse().map_err(|_| err())?,
            b.trim().parse().map_err(|_| err())?,
        ),
        None => {
            let v = s.parse().map_err(|_| err())?;
            (v, v)
        }
    };
    if lo > hi || !(100..=599).contains(&lo) || !(100..=599).contains(&hi) {
        return Err(err());
    }
    Ok((lo, hi))
}

fn json_lookup<'a>(mut v: &'a Value, path: &[String]) -> Option<&'a Value> {
    for seg in path {
        v = match v {
            Value::Object(m) => m.get(seg)?,
            Value::Array(a) => a.get(seg.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(v)
}

/// Equal, or equal once both are rendered as text (`"1"` matches `1`).
fn json_matches(actual: &Value, expected: &Value) -> bool {
    if actual == expected {
        return true;
    }
    let text = |v: &Value| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    text(actual) == text(expected)
}

struct HickoryResolve {
    resolver: TokioResolver,
    version: IpVersion,
}

impl Resolve for HickoryResolve {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.resolver.clone();
        let version = self.version;
        Box::pin(async move {
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            // Same preference as other checks: IPv4 first for `any`; the
            // HTTP client tries the next address when one fails.
            let mut addrs: Vec<SocketAddr> = lookup
                .iter()
                .filter(|ip| match version {
                    IpVersion::Any => true,
                    IpVersion::V4 => ip.is_ipv4(),
                    IpVersion::V6 => ip.is_ipv6(),
                })
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();
            addrs.sort_by_key(|a| a.is_ipv6());
            if addrs.is_empty() {
                return Err(format!("{} has no address matching ip_version", name.as_str()).into());
            }
            let addrs: Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn status_ranges() {
        assert_eq!(parse_status_range("200").unwrap(), (200, 200));
        assert_eq!(parse_status_range("200-299").unwrap(), (200, 299));
        assert_eq!(parse_status_range("3xx").unwrap(), (300, 399));
        assert!(parse_status_range("299-200").is_err());
        assert!(parse_status_range("9xx").is_err());
        assert!(parse_status_range("abc").is_err());
    }

    #[test]
    fn json_paths() {
        let v = json!({"status": "ok", "checks": [{"state": 1}]});
        let path = |p: &str| p.split('.').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(json_lookup(&v, &path("status")), Some(&json!("ok")));
        assert_eq!(json_lookup(&v, &path("checks.0.state")), Some(&json!(1)));
        assert_eq!(json_lookup(&v, &path("checks.1")), None);
        assert!(json_matches(&json!(1), &json!("1")));
        assert!(!json_matches(&json!(true), &json!("false")));
    }
}
