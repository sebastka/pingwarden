//! Configuration: YAML files (or a directory of them) with `${ENV}`/`${file:}`
//! substitution, merged and validated into a [`Config`].

mod duration;
mod interpolate;
mod schema;
mod validate;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

pub use duration::Dur;
pub use schema::*;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("{path}: invalid YAML: {message}")]
    Yaml { path: PathBuf, message: String },
    #[error(transparent)]
    Interpolate(#[from] interpolate::InterpolateError),
    #[error("{file}: {path}: {message}")]
    Schema {
        file: String,
        path: String,
        message: String,
    },
    #[error("{0}")]
    Invalid(String),
    #[error("configuration is invalid:\n  - {}", .0.join("\n  - "))]
    Many(Vec<String>),
}

/// Load configuration from a file, or from every `*.yaml`/`*.yml` file of a
/// directory (sorted by name, merged).
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let files = collect_files(path)?;
    if files.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{}: no *.yaml or *.yml file found",
            path.display()
        )));
    }
    let mut merged = Merged::default();
    for file in &files {
        let text = fs::read_to_string(file).map_err(|source| ConfigError::Io {
            path: file.clone(),
            source,
        })?;
        merged.add(file, &text)?;
    }
    let config = merged.finish()?;
    validate::validate(&config)?;
    Ok(config)
}

/// Parse and validate a single YAML document.
pub fn from_str(text: &str) -> Result<Config, ConfigError> {
    let mut merged = Merged::default();
    merged.add(Path::new("<inline>"), text)?;
    let config = merged.finish()?;
    validate::validate(&config)?;
    Ok(config)
}

fn collect_files(path: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    let meta = fs::metadata(path).map_err(|source| ConfigError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !meta.is_dir() {
        return Ok(vec![path.to_owned()]);
    }
    let mut files = Vec::new();
    let entries = fs::read_dir(path).map_err(|source| ConfigError::Io {
        path: path.to_owned(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        let p = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Skip hidden files, which includes Kubernetes ConfigMap `..data` links.
        if name.starts_with('.') {
            continue;
        }
        let is_yaml = p.extension().is_some_and(|e| e == "yaml" || e == "yml");
        if is_yaml && fs::metadata(&p).is_ok_and(|m| m.is_file()) {
            files.push(p);
        }
    }
    files.sort();
    Ok(files)
}

/// Parsed and interpolated documents, before typed deserialization.
#[derive(Default)]
struct Merged {
    sections: BTreeMap<&'static str, (String, Value)>,
    notifiers: Vec<(String, String, Value)>,
    monitors: Vec<(String, String, Value)>,
    groups: Vec<(String, String, Value)>,
    maintenance: Vec<(String, String, Value)>,
    originals: HashMap<String, String>,
}

const SECTIONS: [&str; 6] = ["server", "database", "retention", "defaults", "tls", "runtime"];

impl Merged {
    fn add(&mut self, file: &Path, text: &str) -> Result<(), ConfigError> {
        let file_name = file.display().to_string();
        let mut doc: Value = if text.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            // YAML 1.2 booleans only: `no`, `y` or `off` stay strings.
            let mut options = serde_saphyr::Options::default();
            options.strict_booleans = true;
            serde_saphyr::from_str_with_options(text, options).map_err(|e| ConfigError::Yaml {
                path: file.to_owned(),
                message: e.to_string(),
            })?
        };
        if doc.is_null() {
            doc = Value::Object(Map::new());
        }
        let Value::Object(top) = doc else {
            return Err(ConfigError::Schema {
                file: file_name,
                path: "<root>".into(),
                message: "expected a mapping".into(),
            });
        };
        for (key, mut value) in top {
            // Paths of interpolated values are prefixed by the file name so
            // that the same path in two files does not collide.
            let mut path = format!("{file_name}#{key}");
            interpolate::interpolate_tree(&mut value, &mut path, &mut self.originals)?;
            match key.as_str() {
                k if SECTIONS.contains(&k) => {
                    let k = SECTIONS.iter().find(|s| **s == k).copied().unwrap_or_default();
                    if let Some((other, _)) = self.sections.get(k) {
                        return Err(ConfigError::Invalid(format!(
                            "section `{k}` is defined in both {other} and {file_name}"
                        )));
                    }
                    self.sections.insert(k, (file_name.clone(), value));
                }
                "notifiers" => match value {
                    Value::Object(map) => {
                        for (id, v) in map {
                            self.notifiers.push((file_name.clone(), id, v));
                        }
                    }
                    Value::Null => {}
                    _ => {
                        return Err(schema_err(
                            &file_name,
                            "notifiers",
                            "expected a mapping of notifier id to notifier",
                        ));
                    }
                },
                "monitors" | "maintenance" | "groups" => {
                    let list = match value {
                        Value::Array(list) => list,
                        Value::Null => Vec::new(),
                        _ => return Err(schema_err(&file_name, &key, "expected a list")),
                    };
                    let target = match key.as_str() {
                        "monitors" => &mut self.monitors,
                        "groups" => &mut self.groups,
                        _ => &mut self.maintenance,
                    };
                    for (i, v) in list.into_iter().enumerate() {
                        target.push((file_name.clone(), format!("{key}[{i}]"), v));
                    }
                }
                _ => {
                    return Err(schema_err(
                        &file_name,
                        &key,
                        "unknown top-level key (expected one of server, database, retention, defaults, tls, runtime, notifiers, groups, monitors, maintenance)",
                    ));
                }
            }
        }
        Ok(())
    }

    fn section<T: DeserializeOwned + Default>(&mut self, name: &'static str) -> Result<T, ConfigError> {
        match self.sections.remove(name) {
            Some((file, value)) => deserialize(value, &file, name, &self.originals),
            None => Ok(T::default()),
        }
    }

    fn finish(mut self) -> Result<Config, ConfigError> {
        let server: ServerConfig = self.section("server")?;
        let database: Option<DatabaseConfig> = match self.sections.remove("database") {
            Some((file, value)) => Some(deserialize(value, &file, "database", &self.originals)?),
            None => None,
        };
        let database = database.ok_or_else(|| ConfigError::Invalid("missing `database` section".into()))?;
        let retention: RetentionConfig = self.section("retention")?;
        let defaults: DefaultsConfig = self.section("defaults")?;
        let tls: TlsConfig = self.section("tls")?;
        let runtime: RuntimeConfig = self.section("runtime")?;

        let mut notifiers = BTreeMap::new();
        for (file, id, value) in std::mem::take(&mut self.notifiers) {
            let path = format!("notifiers.{id}");
            let notifier = parse_notifier(&id, value, &file, &path, &self.originals)?;
            if notifiers.insert(id.clone(), notifier).is_some() {
                return Err(ConfigError::Invalid(format!(
                    "notifier `{id}` is defined more than once"
                )));
            }
        }

        let mut groups: Vec<GroupConfig> = Vec::with_capacity(self.groups.len());
        for (file, path, value) in std::mem::take(&mut self.groups) {
            groups.push(deserialize(value, &file, &path, &self.originals)?);
        }
        let by_id: HashMap<&str, &GroupConfig> = groups.iter().map(|g| (g.id.as_str(), g)).collect();

        let mut monitors = Vec::with_capacity(self.monitors.len());
        for (file, path, value) in std::mem::take(&mut self.monitors) {
            monitors.push(parse_monitor(value, &file, &path, &defaults, &by_id, &self.originals)?);
        }

        let mut maintenance = Vec::with_capacity(self.maintenance.len());
        for (file, path, value) in std::mem::take(&mut self.maintenance) {
            maintenance.push(deserialize(value, &file, &path, &self.originals)?);
        }

        Ok(Config {
            server,
            database,
            retention,
            defaults,
            tls,
            runtime,
            notifiers,
            groups,
            monitors,
            maintenance,
        })
    }
}

fn schema_err(file: &str, path: &str, message: &str) -> ConfigError {
    ConfigError::Schema {
        file: file.to_owned(),
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

/// Deserialize `value`, which lives at `path` in `file`.
///
/// A value that was exactly one `${...}` reference is first offered as a
/// number or boolean; when the target type wants a string instead, the
/// original text is restored and deserialization is retried.
fn deserialize<T: DeserializeOwned>(
    mut value: Value,
    file: &str,
    path: &str,
    originals: &HashMap<String, String>,
) -> Result<T, ConfigError> {
    for _ in 0..256 {
        match serde_path_to_error::deserialize::<_, T>(&value) {
            Ok(v) => return Ok(v),
            Err(err) => {
                let segments: Vec<Segment> = err.path().iter().map(Segment::from).collect();
                let full = render_path(path, &segments);
                let key = format!("{file}#{full}");
                if let Some(original) = originals.get(&key)
                    && let Some(slot) = lookup_mut(&mut value, &segments)
                    && !slot.is_string()
                {
                    *slot = Value::String(original.clone());
                    continue;
                }
                return Err(ConfigError::Schema {
                    file: file.to_owned(),
                    path: full,
                    message: err.into_inner().to_string(),
                });
            }
        }
    }
    Err(schema_err(file, path, "too many type coercions"))
}

enum Segment {
    Index(usize),
    Key(String),
    Other,
}

impl From<&serde_path_to_error::Segment> for Segment {
    fn from(s: &serde_path_to_error::Segment) -> Self {
        match s {
            serde_path_to_error::Segment::Seq { index } => Segment::Index(*index),
            serde_path_to_error::Segment::Map { key } => Segment::Key(key.clone()),
            _ => Segment::Other,
        }
    }
}

fn render_path(prefix: &str, segments: &[Segment]) -> String {
    let mut out = prefix.to_owned();
    for s in segments {
        match s {
            Segment::Index(i) => out.push_str(&format!("[{i}]")),
            Segment::Key(k) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(k);
            }
            Segment::Other => {}
        }
    }
    if out.is_empty() { "<root>".into() } else { out }
}

fn lookup_mut<'a>(value: &'a mut Value, segments: &[Segment]) -> Option<&'a mut Value> {
    let mut cur = value;
    for s in segments {
        cur = match s {
            Segment::Index(i) => cur.get_mut(*i)?,
            Segment::Key(k) => cur.get_mut(k.as_str())?,
            Segment::Other => cur,
        };
    }
    Some(cur)
}

fn take_type(map: &mut Map<String, Value>, file: &str, path: &str) -> Result<String, ConfigError> {
    match map.remove("type") {
        Some(Value::String(t)) => Ok(t),
        Some(_) => Err(schema_err(file, &format!("{path}.type"), "expected a string")),
        None => Err(schema_err(file, path, "missing field `type`")),
    }
}

fn parse_monitor(
    value: Value,
    file: &str,
    path: &str,
    defaults: &DefaultsConfig,
    groups: &HashMap<&str, &GroupConfig>,
    originals: &HashMap<String, String>,
) -> Result<MonitorConfig, ConfigError> {
    let Value::Object(mut map) = value else {
        return Err(schema_err(file, path, "expected a mapping"));
    };
    let kind = take_type(&mut map, file, path)?;
    let mut common = Map::new();
    for key in COMMON_MONITOR_KEYS {
        if let Some(v) = map.remove(*key) {
            common.insert((*key).to_owned(), v);
        }
    }
    let common: CommonMonitorFields = deserialize(Value::Object(common), file, path, originals)?;
    let rest = Value::Object(map);
    let check = match kind.as_str() {
        "icmp" | "ping" => CheckConfig::Icmp(deserialize(rest, file, path, originals)?),
        "tcp" => CheckConfig::Tcp(deserialize(rest, file, path, originals)?),
        "udp" => CheckConfig::Udp(deserialize(rest, file, path, originals)?),
        "http" => CheckConfig::Http(deserialize(rest, file, path, originals)?),
        "tls" | "certificate" => CheckConfig::Tls(deserialize(rest, file, path, originals)?),
        "dns" => CheckConfig::Dns(deserialize(rest, file, path, originals)?),
        "ntp" => CheckConfig::Ntp(deserialize(rest, file, path, originals)?),
        "postgres" | "postgresql" => CheckConfig::Postgres(deserialize(rest, file, path, originals)?),
        "mysql" | "mariadb" => CheckConfig::Mysql(deserialize(rest, file, path, originals)?),
        "push" => CheckConfig::Push(deserialize(rest, file, path, originals)?),
        other => {
            return Err(schema_err(
                file,
                &format!("{path}.type"),
                &format!(
                    "unknown monitor type `{other}` (expected icmp, tcp, udp, http, tls, dns, ntp, postgres, mysql, push)"
                ),
            ));
        }
    };
    let chain = group_chain(common.group(), groups);
    Ok(MonitorConfig::resolve(common, check, defaults, &chain))
}

/// The group of a monitor followed by its ancestors. Unknown ids and cycles
/// end the chain here; validation reports them.
pub(crate) fn group_chain<'a>(start: Option<&str>, groups: &HashMap<&str, &'a GroupConfig>) -> Vec<&'a GroupConfig> {
    let mut chain: Vec<&GroupConfig> = Vec::new();
    let mut next = start;
    while let Some(id) = next {
        let Some(g) = groups.get(id).copied() else { break };
        if chain.iter().any(|c| c.id == g.id) {
            break;
        }
        chain.push(g);
        next = g.parent.as_deref();
    }
    chain
}

fn parse_notifier(
    id: &str,
    value: Value,
    file: &str,
    path: &str,
    originals: &HashMap<String, String>,
) -> Result<NotifierConfig, ConfigError> {
    let Value::Object(mut map) = value else {
        return Err(schema_err(file, path, "expected a mapping"));
    };
    let kind = take_type(&mut map, file, path)?;
    let events: Option<Vec<EventKind>> = match map.remove("events") {
        Some(v) => Some(deserialize(v, file, &format!("{path}.events"), originals)?),
        None => None,
    };
    let rest = Value::Object(map);
    let kind = match kind.as_str() {
        "webhook" => NotifierKind::Webhook(deserialize(rest, file, path, originals)?),
        "ntfy" => NotifierKind::Ntfy(deserialize(rest, file, path, originals)?),
        "gotify" => NotifierKind::Gotify(deserialize(rest, file, path, originals)?),
        "matrix" => NotifierKind::Matrix(deserialize(rest, file, path, originals)?),
        "discord" => NotifierKind::Discord(deserialize(rest, file, path, originals)?),
        "slack" => NotifierKind::Slack(deserialize(rest, file, path, originals)?),
        "telegram" => NotifierKind::Telegram(deserialize(rest, file, path, originals)?),
        "pushover" => NotifierKind::Pushover(deserialize(rest, file, path, originals)?),
        "email" | "smtp" => NotifierKind::Email(deserialize(rest, file, path, originals)?),
        other => {
            return Err(schema_err(
                file,
                &format!("{path}.type"),
                &format!(
                    "unknown notifier type `{other}` (expected webhook, ntfy, gotify, matrix, discord, slack, telegram, pushover, email)"
                ),
            ));
        }
    };
    Ok(NotifierConfig {
        id: id.to_owned(),
        events,
        kind,
    })
}

#[cfg(test)]
mod tests;
