//! Cross-field validation. Every problem is collected so that a single run
//! reports all of them.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use super::{CheckConfig, Config, ConfigError, NotifierKind};
use crate::checks::Check;
use crate::maintenance::Window;

const MIN_SECRET_LEN: usize = 16;

pub fn validate(c: &Config) -> Result<(), ConfigError> {
    let mut errors = Vec::new();
    let mut err = |msg: String| errors.push(msg);

    // server
    if c.server.listen.is_some() && !c.server.listeners.is_empty() {
        err("server: set either `listen` or `listeners`, not both".into());
    }
    let mut addresses = HashSet::new();
    for (i, l) in c.server.listeners.iter().enumerate() {
        if !addresses.insert(l.listen) {
            err(format!(
                "server.listeners[{i}]: {} is used by another listener",
                l.listen
            ));
        }
        if l.serve.is_empty() {
            err(format!("server.listeners[{i}]: `serve` must not be empty"));
        }
        let mut seen = HashSet::new();
        for e in &l.serve {
            if !seen.insert(e) {
                err(format!("server.listeners[{i}]: `{}` is listed twice", e.as_str()));
            }
        }
    }
    let mut token_names = HashSet::new();
    let mut tokens = HashSet::new();
    for t in &c.server.api_tokens {
        if !token_names.insert(&t.name) {
            err(format!("server.api_tokens: duplicate name `{}`", t.name));
        }
        if t.token.len() < MIN_SECRET_LEN {
            err(format!(
                "server.api_tokens.{}: token must be at least {MIN_SECRET_LEN} characters",
                t.name
            ));
        }
        if !tokens.insert(&t.token) {
            err(format!("server.api_tokens.{}: token is reused", t.name));
        }
    }
    if let Some(t) = &c.server.metrics_token
        && t.len() < MIN_SECRET_LEN
    {
        err(format!(
            "server.metrics_token must be at least {MIN_SECRET_LEN} characters"
        ));
    }

    // database
    if !["postgres://", "postgresql://", "mysql://", "mariadb://"]
        .iter()
        .any(|p| c.database.url.starts_with(p))
    {
        err("database.url must start with postgres://, postgresql://, mariadb:// or mysql://".into());
    }
    if c.database.max_connections == 0 {
        err("database.max_connections must be positive".into());
    }

    // runtime
    if c.runtime.worker_threads == 0 || c.runtime.worker_threads > 256 {
        err("runtime.worker_threads must be between 1 and 256".into());
    }
    if c.runtime.max_concurrent_checks == 0 {
        err("runtime.max_concurrent_checks must be positive".into());
    }
    if c.retention.cleanup_interval.0 < Duration::from_secs(60) {
        err("retention.cleanup_interval must be at least 1m".into());
    }

    // notifiers
    for (id, n) in &c.notifiers {
        if !valid_id(id) {
            err(format!(
                "notifiers.{id}: invalid id (use letters, digits, `_`, `-`, `.`)"
            ));
        }
        let urls: Vec<&str> = match &n.kind {
            NotifierKind::Webhook(w) => vec![&w.url],
            NotifierKind::Ntfy(w) => vec![&w.url],
            NotifierKind::Gotify(w) => vec![&w.url],
            NotifierKind::Matrix(w) => vec![&w.homeserver],
            NotifierKind::Discord(w) => vec![&w.webhook_url],
            NotifierKind::Slack(w) => vec![&w.webhook_url],
            NotifierKind::Telegram(w) => vec![&w.api_url],
            NotifierKind::Pushover(_) | NotifierKind::Email(_) => vec![],
        };
        for u in urls {
            match url::Url::parse(u) {
                Ok(u) if matches!(u.scheme(), "http" | "https") => {}
                _ => err(format!("notifiers.{id}: invalid http(s) url")),
            }
        }
        if let NotifierKind::Email(e) = &n.kind {
            if e.to.is_empty() {
                err(format!("notifiers.{id}: `to` must not be empty"));
            }
            for addr in e.to.iter().chain(std::iter::once(&e.from)) {
                if addr.parse::<lettre::message::Mailbox>().is_err() {
                    err(format!("notifiers.{id}: invalid address {addr:?}"));
                }
            }
            if e.username.is_some() != e.password.is_some() {
                err(format!(
                    "notifiers.{id}: set both `username` and `password`, or neither"
                ));
            }
        }
        if let NotifierKind::Ntfy(n) = &n.kind
            && n.priority.is_some_and(|p| !(1..=5).contains(&p))
        {
            err(format!("notifiers.{id}: priority must be between 1 and 5"));
        }
        if let NotifierKind::Webhook(w) = &n.kind
            && reqwest::Method::from_bytes(w.method.to_ascii_uppercase().as_bytes()).is_err()
        {
            err(format!("notifiers.{id}: invalid method {:?}", w.method));
        }
    }
    let check_notify = |owner: &str, list: &[String], err: &mut dyn FnMut(String)| {
        for n in list {
            if !c.notifiers.contains_key(n) {
                err(format!("{owner}: unknown notifier `{n}`"));
            }
        }
    };
    check_notify("defaults.notify", &c.defaults.notify, &mut err);

    // groups
    let mut groups: HashMap<&str, &super::GroupConfig> = HashMap::new();
    for g in &c.groups {
        if !valid_id(&g.id) {
            err(format!(
                "groups.{}: invalid id (use letters, digits, `_`, `-`, `.`; at most 128 characters)",
                g.id
            ));
        }
        if groups.insert(&g.id, g).is_some() {
            err(format!("groups.{}: duplicate group id", g.id));
        }
        check_tags(&format!("groups.{}", g.id), &g.tags, &mut err);
        if let Some(n) = &g.defaults.notify {
            check_notify(&format!("groups.{}.defaults.notify", g.id), n, &mut err);
        }
    }
    for g in &c.groups {
        if let Some(p) = &g.parent {
            if !groups.contains_key(p.as_str()) {
                err(format!("groups.{}: unknown parent group `{p}`", g.id));
            } else if group_has_cycle(&g.id, &groups) {
                err(format!("groups.{}: parent chain forms a cycle", g.id));
            }
        }
    }

    // monitors
    let mut ids = HashSet::new();
    let mut push_tokens = HashMap::new();
    for m in &c.monitors {
        let p = format!("monitors.{}", m.id);
        if !valid_id(&m.id) {
            err(format!(
                "{p}: invalid id (use letters, digits, `_`, `-`, `.`; at most 128 characters)"
            ));
        }
        if !ids.insert(m.id.as_str()) {
            err(format!("{p}: duplicate monitor id"));
        }
        if m.name.chars().count() > 255 {
            err(format!("{p}: name is longer than 255 characters"));
        }
        if let Some(g) = &m.group
            && !groups.contains_key(g.as_str())
        {
            err(format!("{p}: unknown group `{g}`"));
        }
        check_tags(&p, &m.tags, &mut err);
        if m.interval.0 < Duration::from_secs(1) {
            err(format!("{p}: interval must be at least 1s"));
        }
        if m.timeout.is_zero() {
            err(format!("{p}: timeout must be positive"));
        }
        if !matches!(m.check, CheckConfig::Push(_)) && m.timeout > m.interval {
            err(format!(
                "{p}: timeout ({}) must not exceed interval ({})",
                m.timeout, m.interval
            ));
        }
        if m.failure_threshold == 0 || m.recovery_threshold == 0 {
            err(format!(
                "{p}: failure_threshold and recovery_threshold must be at least 1"
            ));
        }
        if let Some(f) = m.flapping
            && (f.max_transitions == 0 || f.window.is_zero())
        {
            err(format!(
                "{p}: flapping.window and flapping.max_transitions must be positive"
            ));
        }
        check_notify(&p, &m.notify, &mut err);
        if let CheckConfig::Push(push) = &m.check {
            if push.token.len() < MIN_SECRET_LEN {
                err(format!("{p}: push token must be at least {MIN_SECRET_LEN} characters"));
            }
            if !push
                .token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                err(format!("{p}: push token may only contain letters, digits, `-` and `_`"));
            }
            if let Some(other) = push_tokens.insert(push.token.as_str(), m.id.as_str()) {
                err(format!("{p}: push token is also used by {other}"));
            }
        }
        if let Err(e) = Check::prepare(&m.check) {
            err(format!("{p}: {e}"));
        }
    }
    for m in &c.monitors {
        for d in &m.depends_on {
            if d == &m.id {
                err(format!("monitors.{}: cannot depend on itself", m.id));
            } else if !ids.contains(d.as_str()) {
                err(format!("monitors.{}: depends_on unknown monitor `{d}`", m.id));
            }
        }
    }
    if let Some(cycle) = dependency_cycle(c) {
        err(format!("depends_on cycle: {}", cycle.join(" -> ")));
    }

    // maintenance
    let mut windows = HashSet::new();
    for w in &c.maintenance {
        let p = format!("maintenance.{}", w.id);
        if !windows.insert(&w.id) {
            err(format!("{p}: duplicate maintenance id"));
        }
        match Window::parse(w) {
            Ok(win) => {
                for id in win.monitor_ids() {
                    if !ids.contains(id) {
                        err(format!("{p}: unknown monitor `{id}`"));
                    }
                }
                for g in win.group_ids() {
                    if !groups.contains_key(g) {
                        err(format!("{p}: unknown group `{g}`"));
                    }
                }
            }
            Err(e) => err(format!("{p}: {e}")),
        }
    }

    match errors.len() {
        0 => Ok(()),
        _ => Err(ConfigError::Many(errors)),
    }
}

pub fn valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && id.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn check_tags(owner: &str, tags: &[String], err: &mut dyn FnMut(String)) {
    let mut seen = HashSet::new();
    for t in tags {
        if t.is_empty() || t.len() > 64 || t.chars().any(|c| c.is_whitespace() || c == ',') {
            err(format!(
                "{owner}: invalid tag {t:?} (1-64 characters, no whitespace or comma)"
            ));
        }
        if !seen.insert(t) {
            err(format!("{owner}: duplicate tag {t:?}"));
        }
    }
}

fn group_has_cycle(start: &str, groups: &HashMap<&str, &super::GroupConfig>) -> bool {
    let mut seen = HashSet::new();
    let mut cur = Some(start);
    while let Some(id) = cur {
        if !seen.insert(id) {
            return true;
        }
        cur = groups.get(id).and_then(|g| g.parent.as_deref());
    }
    false
}

/// Depth-first search for a cycle in `depends_on`.
fn dependency_cycle(c: &Config) -> Option<Vec<String>> {
    let deps: HashMap<&str, &[String]> = c
        .monitors
        .iter()
        .map(|m| (m.id.as_str(), m.depends_on.as_slice()))
        .collect();
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Visiting,
        Done,
    }
    fn visit<'a>(
        id: &'a str,
        deps: &HashMap<&'a str, &'a [String]>,
        marks: &mut HashMap<&'a str, Mark>,
        stack: &mut Vec<&'a str>,
    ) -> Option<Vec<String>> {
        match marks.get(id) {
            Some(Mark::Done) => return None,
            Some(Mark::Visiting) => {
                let start = stack.iter().position(|s| *s == id).unwrap_or(0);
                let mut cycle: Vec<String> = stack[start..].iter().map(|s| (*s).to_owned()).collect();
                cycle.push(id.to_owned());
                return Some(cycle);
            }
            None => {}
        }
        marks.insert(id, Mark::Visiting);
        stack.push(id);
        for d in deps.get(id).copied().unwrap_or_default() {
            if d != id
                && deps.contains_key(d.as_str())
                && let Some(c) = visit(d, deps, marks, stack)
            {
                return Some(c);
            }
        }
        stack.pop();
        marks.insert(id, Mark::Done);
        None
    }
    let mut marks = HashMap::new();
    for m in &c.monitors {
        let mut stack = Vec::new();
        if let Some(c) = visit(&m.id, &deps, &mut marks, &mut stack) {
            return Some(c);
        }
    }
    None
}
