//! The effective configuration of a monitor, for `GET /monitors/{id}/config`:
//! its resolved settings and the check's options, by allow-list. Secrets never
//! appear: passwords, tokens, push tokens, header values, payloads (which may
//! carry credentials) and credentials in URLs are left out.

use serde_json::{Value, json};

use super::{CheckConfig, DnsProtocol, Dur, ExpectMode, IpVersion, MonitorConfig, StartTls, redact_url};

fn secs(d: Dur) -> f64 {
    d.0.as_secs_f64()
}

fn ms(d: Dur) -> f64 {
    d.0.as_secs_f64() * 1000.0
}

fn ip(v: IpVersion) -> &'static str {
    match v {
        IpVersion::Any => "any",
        IpVersion::V4 => "4",
        IpVersion::V6 => "6",
    }
}

fn starttls(s: StartTls) -> Value {
    match s {
        StartTls::None => Value::Null,
        StartTls::Smtp => "smtp".into(),
        StartTls::Imap => "imap".into(),
        StartTls::Pop3 => "pop3".into(),
        StartTls::Ftp => "ftp".into(),
        StartTls::Postgres => "postgres".into(),
        StartTls::Ldap => "ldap".into(),
    }
}

pub fn effective(m: &MonitorConfig) -> Value {
    json!({
        "monitor": m.id,
        "settings": {
            "enabled": m.enabled,
            "interval_seconds": secs(m.interval),
            "timeout_seconds": secs(m.timeout),
            "failure_threshold": m.failure_threshold,
            "recovery_threshold": m.recovery_threshold,
            "renotify_every_seconds": secs(m.renotify_every),
            "notify_degraded": m.notify_degraded,
            "flapping": m.flapping.map(|f| json!({
                "window_seconds": secs(f.window),
                "max_transitions": f.max_transitions,
            })),
            "degraded_latency_ms": m.degraded_latency.map(ms),
            "slo": m.slo,
            "notify": m.notify,
            "depends_on": m.depends_on,
            "group": m.group,
            "tags": m.effective_tags,
        },
        "check": check(&m.check),
    })
}

fn check(c: &CheckConfig) -> Value {
    let mut v = match c {
        CheckConfig::Icmp(c) => json!({
            "host": c.host,
            "count": c.count,
            "packet_size": c.packet_size,
            "packet_timeout_ms": ms(c.packet_timeout),
            "ip_version": ip(c.ip_version),
            "down_loss_percent": c.down_loss_percent,
            "degraded_loss_percent": c.degraded_loss_percent,
        }),
        CheckConfig::Tcp(c) => json!({
            "host": c.host,
            "port": c.port,
            "tls": c.tls,
            "tls_verify": c.tls_verify,
            "sni": c.sni,
            // What is sent may be a login: only whether something is sent.
            "sends_data": c.send.is_some() || c.send_hex.is_some(),
            "expect": c.expect,
            "expect_regex": c.expect_regex,
            "ip_version": ip(c.ip_version),
        }),
        CheckConfig::Udp(c) => json!({
            "host": c.host,
            "port": c.port,
            "sends_payload": c.payload.is_some() || c.payload_hex.is_some(),
            "expect": c.expect,
            "expect_hex": c.expect_hex,
            "expect_regex": c.expect_regex,
            "expect_response": c.expect_response,
            "ip_version": ip(c.ip_version),
        }),
        CheckConfig::Http(c) => json!({
            "url": redact_url(&c.url),
            "method": c.method.to_ascii_uppercase(),
            "header_names": c.headers.keys().collect::<Vec<_>>(),
            "sends_body": c.body.is_some(),
            "auth": if c.basic_auth.is_some() { Some("basic") } else if c.bearer_token.is_some() { Some("bearer") } else { None },
            "accepted_status": c.accepted_status,
            "keyword": c.keyword,
            "keyword_regex": c.keyword_regex,
            "invert_keyword": c.invert_keyword,
            "json_path": c.json_path,
            "json_value": c.json_value,
            "follow_redirects": c.follow_redirects,
            "max_redirects": c.max_redirects,
            "tls_verify": c.tls_verify,
            "max_body_size": c.max_body_size,
            "ip_version": ip(c.ip_version),
        }),
        CheckConfig::Tls(c) => json!({
            "host": c.host,
            "port": c.port,
            "sni": c.sni,
            "starttls": starttls(c.starttls),
            "verify_chain": c.verify_chain,
            "verify_hostname": c.verify_hostname,
            "expiry_warning_seconds": secs(c.expiry_warning),
            "expiry_down_seconds": secs(c.expiry_down),
            "ca_file": c.ca_file,
            "ip_version": ip(c.ip_version),
        }),
        CheckConfig::Dns(c) => json!({
            "domain": c.domain,
            "record_type": c.record_type,
            "server": c.server,
            "protocol": match c.protocol { DnsProtocol::Udp => "udp", DnsProtocol::Tcp => "tcp" },
            "expect": c.expect,
            "expect_mode": match c.expect_mode { ExpectMode::Contains => "contains", ExpectMode::Exact => "exact" },
        }),
        CheckConfig::Ntp(c) => json!({
            "host": c.host,
            "port": c.port,
            "max_offset_ms": ms(c.max_offset),
            "max_offset_down_ms": c.max_offset_down.map(ms),
            "max_stratum": c.max_stratum,
            "ip_version": ip(c.ip_version),
        }),
        CheckConfig::Postgres(c) | CheckConfig::Mysql(c) => json!({
            "url": redact_url(&c.url),
            "query": c.query,
        }),
        // The token is the push monitor's only credential.
        CheckConfig::Push(_) => json!({}),
    };
    if let Value::Object(map) = &mut v {
        map.insert("type".into(), c.type_name().into());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_reveals_secrets() {
        let config = crate::config::from_str(
            r#"
database: { url: "postgres://x@db/x" }
defaults: { slo: 99.5 }
groups:
  - { id: web, defaults: { slo: 99.9, flapping: { window: 1h, max_transitions: 6 } } }
monitors:
  - id: site
    type: http
    group: web
    url: "https://user:SECRET1pass@example.com/health?key=SECRET2key"
    headers: { Authorization: "Bearer SECRET3hdr" }
    body: '{"password": "SECRET4body"}'
    basic_auth: { username: admin, password: SECRET5basic }
    degraded_latency: 2s
  - id: api
    type: http
    url: https://example.com/
    bearer_token: SECRET6bearer
    slo: 99
  - id: db
    type: postgres
    url: "postgres://monitor:SECRET7db@db.example.com/postgres?sslmode=require&password=SECRET8"
  - id: job
    type: push
    token: SECRET9push0123456789
  - id: smtp
    type: tcp
    host: mail.example.com
    port: 25
    send: "AUTH PLAIN SECRET10tcp"
    expect: "220"
  - id: wg
    type: udp
    host: vpn.example.com
    port: 51820
    payload: "SECRET11udp"
    expect_response: false
  - { id: cert, type: tls, host: example.com, starttls: smtp, port: 587 }
  - { id: ping, type: icmp, host: 192.0.2.1 }
  - { id: dns, type: dns, domain: example.com, server: 1.1.1.1 }
  - { id: ntp, type: ntp, host: pool.ntp.org }
"#,
        )
        .unwrap();
        for m in &config.monitors {
            let text = effective(m).to_string();
            assert!(!text.contains("SECRET"), "{}: {text}", m.id);
        }
        let site = effective(&config.monitors[0]);
        assert_eq!(site["check"]["type"], "http");
        assert_eq!(site["check"]["url"], "https://example.com/health");
        assert_eq!(site["check"]["header_names"][0], "Authorization");
        assert_eq!(site["check"]["auth"], "basic");
        assert_eq!(site["settings"]["slo"], 99.9, "group default wins over global");
        assert_eq!(site["settings"]["degraded_latency_ms"], 2000.0);
        assert_eq!(site["settings"]["flapping"]["window_seconds"], 3600.0);
        let api = effective(&config.monitors[1]);
        assert_eq!(api["settings"]["slo"], 99.0);
        assert_eq!(api["check"]["auth"], "bearer");
        assert_eq!(effective(&config.monitors[3])["check"], json!({"type": "push"}));
        assert_eq!(effective(&config.monitors[4])["check"]["sends_data"], true);
        assert_eq!(effective(&config.monitors[6])["check"]["starttls"], "smtp");
    }
}
