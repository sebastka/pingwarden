use super::*;

const BASE: &str = r#"
database:
  url: postgres://pingwarden@db/pingwarden
"#;

fn parse(extra: &str) -> Result<Config, ConfigError> {
    from_str(&format!("{BASE}{extra}"))
}

#[test]
fn minimal_config() {
    let c = parse("").unwrap();
    let listeners = c.server.effective_listeners();
    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].listen.port(), 8080);
    assert_eq!(listeners[0].serve, Endpoints::ALL.to_vec());
    assert!(c.monitors.is_empty());
}

#[test]
fn full_example_parses() {
    let text = include_str!("../../examples/config.yaml");
    let c = from_str(text).unwrap_or_else(|e| panic!("{e}"));
    assert!(c.monitors.len() >= 10);
}

#[test]
fn defaults_and_groups_are_inherited() {
    let c = parse(
        r#"
defaults:
  interval: 30s
  failure_threshold: 2
notifiers:
  ops: { type: webhook, url: "https://example.com/hook" }
  oncall: { type: ntfy, url: "https://ntfy.sh/x" }
groups:
  - id: infra
    tags: [infra]
    defaults: { notify: [ops], timeout: 5s }
  - id: network
    parent: infra
    tags: [net]
    defaults: { interval: 10s }
monitors:
  - id: router
    type: icmp
    host: 192.0.2.1
    group: network
    tags: [critical]
  - id: other
    type: tcp
    host: example.com
    port: 22
    notify: [oncall]
    interval: 15s
"#,
    )
    .unwrap();
    let router = &c.monitors[0];
    assert_eq!(router.interval, Dur::secs(10));
    assert_eq!(router.timeout, Dur::secs(5));
    assert_eq!(router.failure_threshold, 2);
    assert_eq!(router.notify, vec!["ops"]);
    assert_eq!(router.effective_tags, vec!["critical", "net", "infra"]);
    assert_eq!(router.group_path, vec!["network", "infra"]);
    let other = &c.monitors[1];
    assert_eq!(other.interval, Dur::secs(15));
    assert_eq!(other.timeout, Dur::secs(10));
    assert_eq!(other.notify, vec!["oncall"]);
}

#[test]
fn whole_references_coerce_both_ways() {
    let c = parse(
        r#"
notifiers:
  mail:
    type: email
    host: smtp.example.com
    port: "${PW_TEST_UNSET_PORT:-587}"
    username: "${PW_TEST_UNSET_USER:-1234}"
    password: "${PW_TEST_UNSET_PASS:-123456}"
    from: "Pingwarden <pw@example.com>"
    to: ["ops@example.com"]
"#,
    )
    .unwrap();
    let NotifierKind::Email(e) = &c.notifiers["mail"].kind else {
        panic!()
    };
    assert_eq!(e.port, Some(587));
    assert_eq!(e.username.as_deref(), Some("1234"));
    assert_eq!(e.password.as_deref(), Some("123456"));
}

#[test]
fn listeners_split_endpoints() {
    let c = parse(
        r#"
server:
  listeners:
    - listen: 0.0.0.0:8080
      serve: [api, push]
    - listen: 127.0.0.1:9090
      serve: [health, metrics]
"#,
    )
    .unwrap();
    let l = c.server.effective_listeners();
    assert_eq!(l.len(), 2);
    assert_eq!(l[0].serve, vec![Endpoints::Api, Endpoints::Push]);
    assert_eq!(l[1].listen.to_string(), "127.0.0.1:9090");

    let c = parse("server:\n  listen: \"[::]:8081\"\n").unwrap();
    assert_eq!(c.server.effective_listeners()[0].listen.port(), 8081);

    let e = parse(
        "server:\n  listen: 0.0.0.0:1\n  listeners:\n    - { listen: 0.0.0.0:2, serve: [] }\n    - { listen: 0.0.0.0:2, serve: [api, api] }\n",
    )
    .unwrap_err()
    .to_string();
    for needle in [
        "not both",
        "must not be empty",
        "used by another listener",
        "`api` is listed twice",
    ] {
        assert!(e.contains(needle), "missing {needle:?} in:\n{e}");
    }
    let e = parse("server:\n  listeners:\n    - { listen: 0.0.0.0:2, serve: [ui] }\n").unwrap_err();
    assert!(e.to_string().contains("server.listeners[0].serve[0]"), "{e}");
}

#[test]
fn oidc_and_cors_settings() {
    let c = parse(
        r#"
server:
  auth:
    oidc:
      issuer: https://auth.example.com/realms/home
      audience: [pingwarden, pingwarden-ui]
      claim: realm_access.roles
      admin: [pw-admin]
  cors:
    allowed_origins: ["https://ui.example.com", "http://localhost:5173"]
"#,
    )
    .unwrap();
    let o = c.server.auth.oidc.unwrap();
    assert_eq!(o.audience.to_vec(), ["pingwarden", "pingwarden-ui"]);
    assert_eq!(o.leeway, Dur::secs(60));
    assert_eq!(c.server.cors.unwrap().max_age, Dur::secs(600));

    let e = parse(
        r#"
server:
  auth:
    oidc:
      issuer: http://auth.example.com/realms/home
      audience: ""
      claim: "realm_access..roles"
  cors:
    allowed_origins: ["*", "https://ui.example.com/app", "ui.example.com"]
"#,
    )
    .unwrap_err()
    .to_string();
    for needle in [
        "issuer must use https",
        "audience must not be empty",
        "set `read` and/or `admin`",
        "dotted claim path",
        "\"https://ui.example.com/app\" is not an origin",
        "\"ui.example.com\" is not an origin",
        "`*` cannot be combined",
    ] {
        assert!(e.contains(needle), "missing {needle:?} in:\n{e}");
    }
    // http is fine for a local provider (development).
    parse("server:\n  auth:\n    oidc: { issuer: \"http://localhost:8081/realms/dev\", audience: pw, read: [r] }\n")
        .unwrap();
}

#[test]
fn yaml_1_1_booleans_stay_strings() {
    let c = parse("monitors:\n  - { id: y, type: tcp, host: no, port: 1, tags: [on, off] }\n").unwrap();
    assert_eq!(c.monitors[0].id, "y");
    assert_eq!(c.monitors[0].tags, vec!["on", "off"]);
}

#[test]
fn reports_paths_of_schema_errors() {
    let e = parse("monitors:\n  - id: a\n    type: tcp\n    host: h\n    port: nope\n").unwrap_err();
    let msg = e.to_string();
    assert!(msg.contains("monitors[0].port"), "{msg}");

    let e = parse("monitors:\n  - id: a\n    type: tcp\n    host: h\n    port: 1\n    bogus: 1\n").unwrap_err();
    assert!(e.to_string().contains("bogus"), "{e}");

    let e = parse("monitors:\n  - id: a\n    type: gopher\n").unwrap_err();
    assert!(e.to_string().contains("unknown monitor type"), "{e}");

    let e = parse("nonsense: 1\n").unwrap_err();
    assert!(e.to_string().contains("unknown top-level key"), "{e}");
}

#[test]
fn collects_validation_errors() {
    let e = parse(
        r#"
groups:
  - { id: a, parent: b }
  - { id: b, parent: a }
monitors:
  - { id: x, type: tcp, host: h, port: 1, depends_on: [y], notify: [nobody] }
  - { id: y, type: tcp, host: h, port: 1, depends_on: [x], group: ghost }
  - { id: t, type: http, url: "ftp://nope" }
  - { id: p, type: push, token: short }
  - { id: t, type: tcp, host: h, port: 1, timeout: 2m, interval: 1m, tags: ["bad tag"] }
"#,
    )
    .unwrap_err();
    let msg = e.to_string();
    for needle in [
        "unknown notifier `nobody`",
        "duplicate monitor id",
        "unknown group `ghost`",
        "url scheme must be http or https",
        "push token must be at least",
        "timeout (2m) must not exceed interval (1m)",
        "depends_on cycle",
        "parent chain forms a cycle",
        "invalid tag",
    ] {
        assert!(msg.contains(needle), "missing {needle:?} in:\n{msg}");
    }
}

#[test]
fn sections_may_not_be_defined_twice() {
    let mut m = Merged::default();
    m.add(Path::new("a.yaml"), BASE).unwrap();
    m.add(Path::new("b.yaml"), "monitors: []\n").unwrap();
    let e = m.add(Path::new("c.yaml"), BASE).unwrap_err();
    assert!(e.to_string().contains("defined in both a.yaml and c.yaml"), "{e}");
}

#[test]
fn loads_directories_in_order() {
    let dir = std::env::temp_dir().join(format!("pw-config-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("00-base.yaml"), BASE).unwrap();
    std::fs::write(
        dir.join("10-web.yml"),
        "monitors:\n  - { id: web, type: http, url: \"https://example.com\" }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("20-dns.yaml"),
        "monitors:\n  - { id: dns, type: dns, domain: example.com }\n",
    )
    .unwrap();
    std::fs::write(dir.join(".hidden.yaml"), "garbage: [").unwrap();
    std::fs::write(dir.join("README"), "not yaml").unwrap();
    let c = load(&dir).unwrap();
    let ids: Vec<_> = c.monitors.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, ["web", "dns"]);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn slo_is_inherited_and_validated() {
    let c = parse(
        r#"
defaults: { slo: 99.5 }
groups:
  - { id: web, defaults: { slo: 99.9 } }
monitors:
  - { id: a, type: icmp, host: 192.0.2.1, group: web }
  - { id: b, type: icmp, host: 192.0.2.2 }
  - { id: c, type: icmp, host: 192.0.2.3, group: web, slo: 95 }
"#,
    )
    .unwrap();
    let slo: Vec<_> = c.monitors.iter().map(|m| m.slo).collect();
    assert_eq!(slo, [Some(99.9), Some(99.5), Some(95.0)]);
    assert_eq!(
        parse("monitors: [{ id: d, type: icmp, host: 192.0.2.4 }]")
            .unwrap()
            .monitors[0]
            .slo,
        None
    );

    let e = parse(
        r#"
defaults: { slo: 100 }
groups: [{ id: g, defaults: { slo: 0 } }]
monitors: [{ id: m, type: icmp, host: 192.0.2.1, slo: -1 }]
"#,
    )
    .unwrap_err()
    .to_string();
    for owner in ["defaults.slo", "groups.g.defaults.slo", "monitors.m.slo"] {
        assert!(e.contains(&format!("{owner}: must be a percentage")), "{owner}: {e}");
    }
}
