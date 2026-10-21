//! Typed configuration schema. See `docs/configuration.md` for the reference.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Dur;

#[derive(Clone, Debug)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub retention: RetentionConfig,
    pub defaults: DefaultsConfig,
    pub tls: TlsConfig,
    pub runtime: RuntimeConfig,
    pub notifiers: BTreeMap<String, NotifierConfig>,
    pub groups: Vec<GroupConfig>,
    pub monitors: Vec<MonitorConfig>,
    pub maintenance: Vec<MaintenanceConfig>,
}

fn yes() -> bool {
    true
}

// ---------------------------------------------------------------- server

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Shorthand for a single listener serving every endpoint.
    pub listen: Option<SocketAddr>,
    /// Listeners, each serving a chosen set of endpoints.
    pub listeners: Vec<ListenerConfig>,
    /// Bearer tokens accepted by the API.
    pub api_tokens: Vec<ApiToken>,
    /// Allow unauthenticated read-only API access.
    pub anonymous_read: bool,
    /// Bearer token required by `/metrics`; open when unset.
    pub metrics_token: Option<String>,
    /// Token validation besides `api_tokens`.
    pub auth: AuthConfig,
    /// Cross-origin access for browser UIs.
    pub cors: Option<CorsConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthConfig {
    /// Accept JWT access tokens issued by an OpenID Connect provider.
    pub oidc: Option<OidcConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Issuer URL, exactly as in the tokens' `iss` claim.
    pub issuer: String,
    /// Accepted `aud` values; a token must carry at least one.
    pub audience: OneOrMany,
    /// Claim holding the permissions: a space-separated string (`scope`) or
    /// a list (`groups`, `roles`). Dots descend into objects, e.g.
    /// `realm_access.roles`.
    #[serde(default = "OidcConfig::default_claim")]
    pub claim: String,
    /// Claim values granting read access.
    #[serde(default)]
    pub read: Vec<String>,
    /// Claim values granting admin access (which includes read).
    #[serde(default)]
    pub admin: Vec<String>,
    /// JWKS URL; discovered from the issuer when unset.
    pub jwks_url: Option<String>,
    /// How often signing keys are refreshed.
    #[serde(default = "OidcConfig::default_refresh")]
    pub jwks_refresh: Dur,
    /// Clock skew tolerated on `exp` and `nbf`.
    #[serde(default = "OidcConfig::default_leeway")]
    pub leeway: Dur,
}

impl OidcConfig {
    fn default_claim() -> String {
        "scope".into()
    }
    fn default_refresh() -> Dur {
        Dur::secs(3600)
    }
    fn default_leeway() -> Dur {
        Dur::secs(60)
    }
}

/// A string or a list of strings.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s.clone()],
            OneOrMany::Many(v) => v.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Origins allowed to call the API from a browser, e.g.
    /// `https://ui.example.com`, or `*` for any.
    pub allowed_origins: Vec<String>,
    /// How long browsers may cache preflight responses.
    #[serde(default = "CorsConfig::default_max_age")]
    pub max_age: Dur,
}

impl CorsConfig {
    fn default_max_age() -> Dur {
        Dur::secs(600)
    }
}

pub const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 8080);

impl ServerConfig {
    /// The listeners to open: `listeners`, else `listen` (or the default
    /// address) serving everything.
    pub fn effective_listeners(&self) -> Vec<ListenerConfig> {
        if !self.listeners.is_empty() {
            return self.listeners.clone();
        }
        vec![ListenerConfig {
            listen: self.listen.unwrap_or(DEFAULT_LISTEN),
            serve: Endpoints::ALL.to_vec(),
        }]
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub listen: SocketAddr,
    /// Endpoint groups served on this address; all of them when omitted.
    #[serde(default = "Endpoints::all")]
    pub serve: Vec<Endpoints>,
}

/// Groups of HTTP endpoints that can be assigned to listeners.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Endpoints {
    /// `/healthz` and `/readyz`.
    Health,
    /// `/metrics`.
    Metrics,
    /// `/api/v1/…`, except push.
    Api,
    /// `/api/v1/push/{token}`.
    Push,
}

impl Endpoints {
    pub const ALL: [Endpoints; 4] = [Endpoints::Health, Endpoints::Metrics, Endpoints::Api, Endpoints::Push];

    fn all() -> Vec<Endpoints> {
        Self::ALL.to_vec()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Endpoints::Health => "health",
            Endpoints::Metrics => "metrics",
            Endpoints::Api => "api",
            Endpoints::Push => "push",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiToken {
    pub name: String,
    pub token: String,
    #[serde(default)]
    pub scope: TokenScope,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum TokenScope {
    #[default]
    Read,
    Admin,
}

// -------------------------------------------------------------- database

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// `postgres://…` or `mysql://…` / `mariadb://…`.
    pub url: String,
    #[serde(default = "DatabaseConfig::default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "DatabaseConfig::default_connect_timeout")]
    pub connect_timeout: Dur,
    /// Name of the advisory lock that elects the active instance.
    #[serde(default = "DatabaseConfig::default_lock_name")]
    pub lock_name: String,
}

impl DatabaseConfig {
    fn default_max_connections() -> u32 {
        4
    }
    fn default_connect_timeout() -> Dur {
        Dur::secs(10)
    }
    fn default_lock_name() -> String {
        "pingwarden".into()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RetentionConfig {
    /// Raw check results. `0` keeps them forever.
    pub heartbeats: Dur,
    pub hourly: Dur,
    pub daily: Dur,
    pub events: Dur,
    pub notifications: Dur,
    /// History of monitors removed from the configuration.
    pub removed_monitors: Dur,
    pub cleanup_interval: Dur,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            heartbeats: Dur::secs(14 * 86_400),
            hourly: Dur::secs(400 * 86_400),
            daily: Dur::ZERO,
            events: Dur::secs(400 * 86_400),
            notifications: Dur::secs(90 * 86_400),
            removed_monitors: Dur::secs(30 * 86_400),
            cleanup_interval: Dur::secs(3600),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DefaultsConfig {
    pub interval: Dur,
    pub timeout: Dur,
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
    pub notify: Vec<String>,
    pub renotify_every: Dur,
    pub notify_degraded: bool,
    pub flapping: Option<FlapConfig>,
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            interval: Dur::secs(60),
            timeout: Dur::secs(10),
            failure_threshold: 3,
            recovery_threshold: 1,
            notify: Vec::new(),
            renotify_every: Dur::ZERO,
            notify_degraded: true,
            flapping: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FlapConfig {
    pub window: Dur,
    pub max_transitions: u32,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    /// Extra PEM CA bundles trusted by every TLS-based check.
    pub ca_files: Vec<PathBuf>,
    /// Do not load the system trust store.
    pub disable_system_roots: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeConfig {
    /// Tokio worker threads; `1` selects the single-threaded runtime.
    pub worker_threads: usize,
    /// Upper bound of checks running at the same time.
    pub max_concurrent_checks: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: 2,
            max_concurrent_checks: 64,
        }
    }
}

// ------------------------------------------------------------- notifiers

#[derive(Clone, Debug)]
pub struct NotifierConfig {
    pub id: String,
    /// Events this notifier receives; all of them when unset.
    pub events: Option<Vec<EventKind>>,
    pub kind: NotifierKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Down,
    Up,
    Degraded,
    Reminder,
    Flapping,
    Test,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Down => "down",
            EventKind::Up => "up",
            EventKind::Degraded => "degraded",
            EventKind::Reminder => "reminder",
            EventKind::Flapping => "flapping",
            EventKind::Test => "test",
        }
    }
}

#[derive(Clone, Debug)]
pub enum NotifierKind {
    Webhook(WebhookNotifier),
    Ntfy(NtfyNotifier),
    Gotify(GotifyNotifier),
    Matrix(MatrixNotifier),
    Discord(DiscordNotifier),
    Slack(SlackNotifier),
    Telegram(TelegramNotifier),
    Pushover(PushoverNotifier),
    Email(EmailNotifier),
}

impl NotifierKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            NotifierKind::Webhook(_) => "webhook",
            NotifierKind::Ntfy(_) => "ntfy",
            NotifierKind::Gotify(_) => "gotify",
            NotifierKind::Matrix(_) => "matrix",
            NotifierKind::Discord(_) => "discord",
            NotifierKind::Slack(_) => "slack",
            NotifierKind::Telegram(_) => "telegram",
            NotifierKind::Pushover(_) => "pushover",
            NotifierKind::Email(_) => "email",
        }
    }
}

fn default_post() -> String {
    "POST".into()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookNotifier {
    pub url: String,
    #[serde(default = "default_post")]
    pub method: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyNotifier {
    /// Topic URL, e.g. `https://ntfy.sh/my-topic`.
    pub url: String,
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Priority (1-5) of down notifications; others use the default.
    pub priority: Option<u8>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GotifyNotifier {
    pub url: String,
    pub token: String,
    pub priority: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixNotifier {
    pub homeserver: String,
    pub room_id: String,
    pub access_token: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscordNotifier {
    pub webhook_url: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlackNotifier {
    pub webhook_url: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramNotifier {
    pub bot_token: String,
    pub chat_id: String,
    #[serde(default = "TelegramNotifier::default_api_url")]
    pub api_url: String,
}

impl TelegramNotifier {
    fn default_api_url() -> String {
        "https://api.telegram.org".into()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushoverNotifier {
    pub user_key: String,
    pub app_token: String,
    pub priority: Option<i8>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SmtpSecurity {
    #[default]
    Starttls,
    Tls,
    None,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailNotifier {
    pub host: String,
    pub port: Option<u16>,
    #[serde(default)]
    pub security: SmtpSecurity,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
}

// -------------------------------------------------------------- monitors

/// Keys shared by every monitor type; everything else belongs to the check.
pub(super) const COMMON_MONITOR_KEYS: &[&str] = &[
    "id",
    "name",
    "description",
    "tags",
    "enabled",
    "interval",
    "timeout",
    "failure_threshold",
    "recovery_threshold",
    "notify",
    "renotify_every",
    "notify_degraded",
    "flapping",
    "depends_on",
    "degraded_latency",
    "group",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommonMonitorFields {
    id: String,
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "yes")]
    enabled: bool,
    interval: Option<Dur>,
    timeout: Option<Dur>,
    failure_threshold: Option<u32>,
    recovery_threshold: Option<u32>,
    notify: Option<Vec<String>>,
    renotify_every: Option<Dur>,
    notify_degraded: Option<bool>,
    /// `false` disables flap detection inherited from the defaults.
    flapping: Option<FlapSetting>,
    #[serde(default)]
    depends_on: Vec<String>,
    degraded_latency: Option<Dur>,
    group: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum FlapSetting {
    Enabled(FlapConfig),
    Toggle(bool),
}

#[derive(Clone, Debug)]
pub struct MonitorConfig {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub interval: Dur,
    pub timeout: Dur,
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
    pub notify: Vec<String>,
    pub renotify_every: Dur,
    pub notify_degraded: bool,
    pub flapping: Option<FlapConfig>,
    pub depends_on: Vec<String>,
    pub degraded_latency: Option<Dur>,
    pub group: Option<String>,
    /// The group and its ancestors, nearest first.
    pub group_path: Vec<String>,
    /// Own tags followed by the tags inherited from the group chain.
    pub effective_tags: Vec<String>,
    pub check: CheckConfig,
}

impl CommonMonitorFields {
    pub(super) fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }
}

impl MonitorConfig {
    /// Apply inherited settings: the monitor's own value wins, then each group
    /// from the nearest to the root, then the global defaults.
    pub(super) fn resolve(
        c: CommonMonitorFields,
        check: CheckConfig,
        d: &DefaultsConfig,
        chain: &[&GroupConfig],
    ) -> Self {
        macro_rules! inherit {
            ($field:ident) => {
                c.$field
                    .clone()
                    .or_else(|| chain.iter().find_map(|g| g.defaults.$field.clone()))
            };
        }
        let flapping = match inherit!(flapping) {
            None | Some(FlapSetting::Toggle(true)) => d.flapping,
            Some(FlapSetting::Toggle(false)) => None,
            Some(FlapSetting::Enabled(f)) => Some(f),
        };
        let mut effective_tags = c.tags.clone();
        for g in chain {
            for t in &g.tags {
                if !effective_tags.contains(t) {
                    effective_tags.push(t.clone());
                }
            }
        }
        Self {
            name: c.name.clone().unwrap_or_else(|| c.id.clone()),
            interval: inherit!(interval).unwrap_or(d.interval),
            timeout: inherit!(timeout).unwrap_or(d.timeout),
            failure_threshold: inherit!(failure_threshold).unwrap_or(d.failure_threshold),
            recovery_threshold: inherit!(recovery_threshold).unwrap_or(d.recovery_threshold),
            notify: inherit!(notify).unwrap_or_else(|| d.notify.clone()),
            renotify_every: inherit!(renotify_every).unwrap_or(d.renotify_every),
            notify_degraded: inherit!(notify_degraded).unwrap_or(d.notify_degraded),
            degraded_latency: inherit!(degraded_latency),
            flapping,
            id: c.id,
            description: c.description,
            tags: c.tags,
            effective_tags,
            enabled: c.enabled,
            depends_on: c.depends_on,
            group: c.group,
            group_path: chain.iter().map(|g| g.id.clone()).collect(),
            check,
        }
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        self.effective_tags.iter().any(|t| t == tag)
    }
}

// ---------------------------------------------------------------- groups

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupStatusPolicy {
    /// The group is down when any member is down.
    #[default]
    AnyDown,
    /// The group is down only when every member is down (redundant services).
    AllDown,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupConfig {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Enclosing group, for nesting.
    pub parent: Option<String>,
    #[serde(default)]
    pub status_policy: GroupStatusPolicy,
    /// Settings inherited by member monitors (and subgroups' members).
    #[serde(default)]
    pub defaults: GroupDefaults,
}

impl GroupConfig {
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupDefaults {
    pub interval: Option<Dur>,
    pub timeout: Option<Dur>,
    pub failure_threshold: Option<u32>,
    pub recovery_threshold: Option<u32>,
    pub notify: Option<Vec<String>>,
    pub renotify_every: Option<Dur>,
    pub notify_degraded: Option<bool>,
    pub flapping: Option<FlapSetting>,
    pub degraded_latency: Option<Dur>,
}

#[derive(Clone, Debug)]
pub enum CheckConfig {
    Icmp(IcmpCheck),
    Tcp(TcpCheck),
    Udp(UdpCheck),
    Http(HttpCheck),
    Tls(TlsCheck),
    Dns(DnsCheck),
    Ntp(NtpCheck),
    Postgres(DatabaseCheck),
    Mysql(DatabaseCheck),
    Push(PushCheck),
}

impl CheckConfig {
    pub fn type_name(&self) -> &'static str {
        match self {
            CheckConfig::Icmp(_) => "icmp",
            CheckConfig::Tcp(_) => "tcp",
            CheckConfig::Udp(_) => "udp",
            CheckConfig::Http(_) => "http",
            CheckConfig::Tls(_) => "tls",
            CheckConfig::Dns(_) => "dns",
            CheckConfig::Ntp(_) => "ntp",
            CheckConfig::Postgres(_) => "postgres",
            CheckConfig::Mysql(_) => "mysql",
            CheckConfig::Push(_) => "push",
        }
    }

    /// Human-readable target, free of credentials.
    pub fn target(&self) -> String {
        match self {
            CheckConfig::Icmp(c) => c.host.clone(),
            CheckConfig::Tcp(c) => host_port(&c.host, c.port),
            CheckConfig::Udp(c) => host_port(&c.host, c.port),
            CheckConfig::Http(c) => redact_url(&c.url),
            CheckConfig::Tls(c) => host_port(&c.host, c.port),
            CheckConfig::Dns(c) => match &c.server {
                Some(s) => format!("{} {} @{s}", c.domain, c.record_type),
                None => format!("{} {}", c.domain, c.record_type),
            },
            CheckConfig::Ntp(c) => host_port(&c.host, c.port),
            CheckConfig::Postgres(c) | CheckConfig::Mysql(c) => redact_url(&c.url),
            CheckConfig::Push(_) => "push".into(),
        }
    }
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Strip user info, query and fragment from a URL.
pub fn redact_url(raw: &str) -> String {
    match url::Url::parse(raw) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => "<invalid url>".into(),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IpVersion {
    #[default]
    Any,
    V4,
    V6,
}

impl<'de> Deserialize<'de> for IpVersion {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u8),
            Text(String),
        }
        let text = match Raw::deserialize(d)? {
            Raw::Num(n) => n.to_string(),
            Raw::Text(t) => t.to_ascii_lowercase(),
        };
        match text.as_str() {
            "any" => Ok(IpVersion::Any),
            "4" | "ipv4" | "v4" => Ok(IpVersion::V4),
            "6" | "ipv6" | "v6" => Ok(IpVersion::V6),
            other => Err(serde::de::Error::custom(format!(
                "invalid ip_version `{other}`, expected any, 4 or 6"
            ))),
        }
    }
}

fn d_count() -> u32 {
    3
}
fn d_packet_size() -> usize {
    56
}
fn d_packet_timeout() -> Dur {
    Dur::secs(1)
}
fn d_down_loss() -> f64 {
    100.0
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IcmpCheck {
    pub host: String,
    #[serde(default = "d_count")]
    pub count: u32,
    /// ICMP payload size in bytes.
    #[serde(default = "d_packet_size")]
    pub packet_size: usize,
    #[serde(default = "d_packet_timeout")]
    pub packet_timeout: Dur,
    #[serde(default)]
    pub ip_version: IpVersion,
    /// Packet loss (percent) at or above which the host is down.
    #[serde(default = "d_down_loss")]
    pub down_loss_percent: f64,
    /// Packet loss (percent) at or above which the host is degraded.
    pub degraded_loss_percent: Option<f64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpCheck {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub tls: bool,
    #[serde(default = "yes")]
    pub tls_verify: bool,
    pub sni: Option<String>,
    /// Bytes to send after connecting; supports `\n`, `\r`, `\t`, `\0`, `\xHH`.
    pub send: Option<String>,
    pub send_hex: Option<String>,
    /// Substring expected in the first bytes received.
    pub expect: Option<String>,
    pub expect_regex: Option<String>,
    #[serde(default)]
    pub ip_version: IpVersion,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpCheck {
    pub host: String,
    pub port: u16,
    pub payload: Option<String>,
    pub payload_hex: Option<String>,
    pub expect: Option<String>,
    pub expect_hex: Option<String>,
    pub expect_regex: Option<String>,
    /// When `false`, silence counts as up and only an ICMP port-unreachable
    /// marks the port down. See docs/checks.md for why this is weak.
    #[serde(default = "yes")]
    pub expect_response: bool,
    #[serde(default)]
    pub ip_version: IpVersion,
}

fn d_get() -> String {
    "GET".into()
}
fn d_status() -> Vec<String> {
    vec!["200-299".into()]
}
fn d_redirects() -> usize {
    10
}
fn d_body_size() -> usize {
    1024 * 1024
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCheck {
    pub url: String,
    #[serde(default = "d_get")]
    pub method: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    /// Accepted status codes or ranges, e.g. `["200-299", "401"]`.
    #[serde(default = "d_status")]
    pub accepted_status: Vec<String>,
    pub keyword: Option<String>,
    pub keyword_regex: Option<String>,
    /// Fail when the keyword *is* found.
    #[serde(default)]
    pub invert_keyword: bool,
    /// Dotted path into a JSON response, e.g. `status` or `checks.0.state`.
    pub json_path: Option<String>,
    /// Value expected at `json_path`.
    pub json_value: Option<Value>,
    #[serde(default = "yes")]
    pub follow_redirects: bool,
    #[serde(default = "d_redirects")]
    pub max_redirects: usize,
    #[serde(default = "yes")]
    pub tls_verify: bool,
    pub basic_auth: Option<BasicAuth>,
    pub bearer_token: Option<String>,
    /// Bytes of body read for keyword and JSON matching.
    #[serde(default = "d_body_size")]
    pub max_body_size: usize,
    #[serde(default)]
    pub ip_version: IpVersion,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicAuth {
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StartTls {
    #[default]
    None,
    Smtp,
    Imap,
    Pop3,
    Ftp,
    Postgres,
    Ldap,
}

fn d_443() -> u16 {
    443
}
fn d_expiry_warning() -> Dur {
    Dur::secs(14 * 86_400)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsCheck {
    pub host: String,
    #[serde(default = "d_443")]
    pub port: u16,
    /// Server name sent in SNI and verified; defaults to `host`.
    pub sni: Option<String>,
    #[serde(default)]
    pub starttls: StartTls,
    #[serde(default = "yes")]
    pub verify_chain: bool,
    #[serde(default = "yes")]
    pub verify_hostname: bool,
    /// Degraded when the leaf (or any intermediate) expires within this delay.
    #[serde(default = "d_expiry_warning")]
    pub expiry_warning: Dur,
    /// Down when it expires within this delay (`0`: once expired).
    #[serde(default)]
    pub expiry_down: Dur,
    /// Extra PEM CA bundle for this monitor.
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub ip_version: IpVersion,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    #[default]
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExpectMode {
    /// Every expected value must be present.
    #[default]
    Contains,
    /// The answer must be exactly the expected set.
    Exact,
}

fn d_record_type() -> String {
    "A".into()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsCheck {
    /// Name to query (`name` is the monitor's display name).
    pub domain: String,
    #[serde(default = "d_record_type")]
    pub record_type: String,
    /// `ip` or `ip:port`; the system resolver when unset.
    pub server: Option<String>,
    #[serde(default)]
    pub protocol: DnsProtocol,
    #[serde(default)]
    pub expect: Vec<String>,
    #[serde(default)]
    pub expect_mode: ExpectMode,
}

fn d_123() -> u16 {
    123
}
fn d_max_offset() -> Dur {
    Dur::secs(1)
}
fn d_max_stratum() -> u8 {
    15
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtpCheck {
    pub host: String,
    #[serde(default = "d_123")]
    pub port: u16,
    /// Degraded when the absolute clock offset exceeds this.
    #[serde(default = "d_max_offset")]
    pub max_offset: Dur,
    /// Down when the absolute clock offset exceeds this.
    pub max_offset_down: Option<Dur>,
    /// Degraded when the server stratum is above this.
    #[serde(default = "d_max_stratum")]
    pub max_stratum: u8,
    #[serde(default)]
    pub ip_version: IpVersion,
}

fn d_select_1() -> String {
    "SELECT 1".into()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseCheck {
    pub url: String,
    #[serde(default = "d_select_1")]
    pub query: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushCheck {
    /// Secret path segment of `/api/v1/push/{token}`.
    pub token: String,
}

// ----------------------------------------------------------- maintenance

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceConfig {
    pub id: String,
    pub description: Option<String>,
    /// Applies to every monitor.
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub monitors: Vec<String>,
    /// Applies to monitors carrying any of these tags (own or inherited).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Applies to members of these groups, including nested groups.
    #[serde(default)]
    pub groups: Vec<String>,
    /// One-off window: RFC 3339 timestamps.
    pub start: Option<String>,
    pub end: Option<String>,
    pub recurring: Option<RecurringWindow>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecurringWindow {
    /// Days the window starts on; every day when empty.
    #[serde(default)]
    pub days: Vec<Weekday>,
    /// Local start time, `HH:MM`.
    pub start: String,
    pub duration: Dur,
    #[serde(default = "RecurringWindow::default_tz")]
    pub timezone: String,
}

impl RecurringWindow {
    fn default_tz() -> String {
        "UTC".into()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    #[serde(alias = "monday")]
    Mon,
    #[serde(alias = "tuesday")]
    Tue,
    #[serde(alias = "wednesday")]
    Wed,
    #[serde(alias = "thursday")]
    Thu,
    #[serde(alias = "friday")]
    Fri,
    #[serde(alias = "saturday")]
    Sat,
    #[serde(alias = "sunday")]
    Sun,
}
