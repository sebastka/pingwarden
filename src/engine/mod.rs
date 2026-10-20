//! The engine runs while this instance holds the leader lock: one task per
//! monitor, the database writer, the notification dispatcher and the
//! retention job. Configuration reloads are reconciled in place.

mod monitor;
pub mod state;
pub mod writer;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{Mutex, Semaphore, oneshot};
use tokio_util::sync::CancellationToken;

pub use monitor::PushReport;
use monitor::{Command, MonitorHandle};
use state::MonitorState;
use writer::Writer;

use crate::checks::{Check, CheckContext};
use crate::config::{CheckConfig, Config, GroupConfig, GroupStatusPolicy, MonitorConfig};
use crate::maintenance::Window;
use crate::metrics::Metrics;
use crate::model::{Status, now_ms};
use crate::notify::Dispatcher;
use crate::store::{MonitorMeta, Store};

/// Live view of a monitor, served by the API.
#[derive(Clone, Debug, Serialize)]
pub struct LiveView {
    pub status: Status,
    pub since: i64,
    /// Outcome of the last check (before hysteresis).
    pub outcome: Option<Status>,
    pub last_check: Option<i64>,
    pub latency_ms: Option<f64>,
    pub message: Option<String>,
    pub paused: bool,
    pub flapping: bool,
    pub maintenance: Option<String>,
    pub cert_expiry: Option<i64>,
    pub consecutive_failures: u32,
}

impl Default for LiveView {
    fn default() -> Self {
        Self {
            status: Status::Unknown,
            since: now_ms(),
            outcome: None,
            last_check: None,
            latency_ms: None,
            message: None,
            paused: false,
            flapping: false,
            maintenance: None,
            cert_expiry: None,
            consecutive_failures: 0,
        }
    }
}

/// State shared by the monitor tasks.
pub struct Shared {
    pub ctx: CheckContext,
    pub writer: Writer,
    pub dispatcher: Dispatcher,
    pub metrics: Metrics,
    pub live: RwLock<HashMap<String, LiveView>>,
    maintenance: RwLock<Arc<Vec<Window>>>,
    semaphore: Semaphore,
}

impl Shared {
    /// Id of the maintenance window covering `monitor` at `ts`, if any.
    pub fn maintenance_for(&self, monitor: &MonitorConfig, ts: i64) -> Option<String> {
        let windows = self.maintenance.read().ok()?.clone();
        windows
            .iter()
            .find(|w| w.applies_to(monitor) && w.active_until(ts).is_some())
            .map(|w| w.id.clone())
    }
}

pub struct Engine {
    shared: Arc<Shared>,
    store: Store,
    config: RwLock<Arc<Config>>,
    monitors: Mutex<HashMap<String, MonitorHandle>>,
    push_tokens: RwLock<HashMap<String, String>>,
    cancel: CancellationToken,
    writer_cancel: CancellationToken,
    background: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("unknown monitor")]
    UnknownMonitor,
    #[error("monitor is disabled")]
    Disabled,
    #[error("monitor is busy")]
    Busy,
}

fn meta(m: &MonitorConfig) -> MonitorMeta {
    MonitorMeta {
        id: m.id.clone(),
        name: m.name.clone(),
        kind: m.check.type_name().into(),
        target: m.check.target(),
        description: m.description.clone(),
    }
}

fn windows(config: &Config) -> Vec<Window> {
    // Validated at load time; a failure here cannot happen.
    config
        .maintenance
        .iter()
        .filter_map(|w| Window::parse(w).ok())
        .collect()
}

fn push_tokens(config: &Config) -> HashMap<String, String> {
    config
        .monitors
        .iter()
        .filter(|m| m.enabled)
        .filter_map(|m| match &m.check {
            CheckConfig::Push(p) => Some((p.token.clone(), m.id.clone())),
            _ => None,
        })
        .collect()
}

/// Two monitor configurations are equivalent when nothing that affects the
/// running task differs (including inherited settings).
fn same_monitor(a: &MonitorConfig, b: &MonitorConfig) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

impl Engine {
    pub async fn start(config: Arc<Config>, store: Store, metrics: Metrics) -> anyhow::Result<Arc<Self>> {
        let metas: Vec<_> = config.monitors.iter().map(meta).collect();
        store.sync_monitors(&metas, now_ms()).await?;
        let persisted = store.load_states().await?;

        let cancel = CancellationToken::new();
        let writer_cancel = CancellationToken::new();
        let (writer, writer_task) = Writer::spawn(store.clone(), metrics.clone(), writer_cancel.clone());
        let dispatcher = Dispatcher::spawn(
            config.notifiers.clone(),
            writer.clone(),
            metrics.clone(),
            cancel.clone(),
        )?;
        let ctx = CheckContext::new(&config.tls)?;
        let shared = Arc::new(Shared {
            ctx,
            writer,
            dispatcher,
            metrics: metrics.clone(),
            live: RwLock::new(HashMap::new()),
            maintenance: RwLock::new(Arc::new(windows(&config))),
            semaphore: Semaphore::new(config.runtime.max_concurrent_checks),
        });

        let mut handles = HashMap::new();
        for m in &config.monitors {
            metrics.register_monitor(m);
            let state = persisted
                .get(&m.id)
                .map(MonitorState::restore)
                .unwrap_or_else(|| MonitorState::new(now_ms()));
            if let Some(h) = Self::spawn_monitor(m, state, &shared, &cancel) {
                handles.insert(m.id.clone(), h);
            }
        }
        tracing::info!(monitors = handles.len(), "engine started");

        let engine = Arc::new(Self {
            shared,
            store,
            push_tokens: RwLock::new(push_tokens(&config)),
            config: RwLock::new(config),
            monitors: Mutex::new(handles),
            cancel,
            writer_cancel,
            background: Mutex::new(vec![writer_task]),
        });
        let cleanup = tokio::spawn(engine.clone().cleanup_loop());
        let groups = tokio::spawn(engine.clone().group_metrics_loop());
        engine.background.lock().await.extend([cleanup, groups]);
        Ok(engine)
    }

    fn spawn_monitor(
        m: &MonitorConfig,
        state: MonitorState,
        shared: &Arc<Shared>,
        cancel: &CancellationToken,
    ) -> Option<MonitorHandle> {
        if !m.enabled {
            if let Ok(mut live) = shared.live.write() {
                live.insert(
                    m.id.clone(),
                    LiveView {
                        status: Status::Paused,
                        paused: true,
                        message: Some("disabled in configuration".into()),
                        ..LiveView::default()
                    },
                );
            }
            shared.metrics.set_status(&m.id, Status::Paused);
            return None;
        }
        match Check::prepare(&m.check) {
            Ok(check) => Some(monitor::spawn(
                Arc::new(m.clone()),
                check,
                state,
                shared.clone(),
                cancel,
            )),
            Err(e) => {
                // Validation runs the same code, so this is unreachable in practice.
                tracing::error!(monitor = %m.id, error = %e, "invalid monitor");
                None
            }
        }
    }

    pub fn config(&self) -> Arc<Config> {
        self.config.read().map(|c| c.clone()).expect("config lock poisoned")
    }

    pub fn live(&self) -> HashMap<String, LiveView> {
        self.shared.live.read().map(|l| l.clone()).unwrap_or_default()
    }

    pub fn dispatcher(&self) -> &Dispatcher {
        &self.shared.dispatcher
    }

    /// Reconcile running monitors with a new configuration.
    pub async fn apply(&self, new: Arc<Config>) -> anyhow::Result<()> {
        let old = self.config();
        for (name, a, b) in [
            ("server", format!("{:?}", old.server), format!("{:?}", new.server)),
            ("database", format!("{:?}", old.database), format!("{:?}", new.database)),
            ("tls", format!("{:?}", old.tls), format!("{:?}", new.tls)),
            ("runtime", format!("{:?}", old.runtime), format!("{:?}", new.runtime)),
        ] {
            if a != b {
                tracing::warn!(
                    section = name,
                    "configuration section changed; restart Pingwarden to apply it"
                );
            }
        }
        let metas: Vec<_> = new.monitors.iter().map(meta).collect();
        self.store.sync_monitors(&metas, now_ms()).await?;

        self.shared.dispatcher.replace_notifiers(new.notifiers.clone());
        if let Ok(mut m) = self.shared.maintenance.write() {
            *m = Arc::new(windows(&new));
        }

        let mut handles = self.monitors.lock().await;
        let (mut added, mut changed, mut removed) = (0, 0, 0);
        let wanted: HashMap<&str, &MonitorConfig> = new.monitors.iter().map(|m| (m.id.as_str(), m)).collect();

        let ids: Vec<String> = handles.keys().cloned().collect();
        for id in ids {
            if !wanted.get(id.as_str()).is_some_and(|m| m.enabled) {
                if let Some(h) = handles.remove(&id) {
                    h.stop().await;
                }
                if !wanted.contains_key(id.as_str()) {
                    self.forget(&id);
                    removed += 1;
                }
            }
        }
        // Disabled monitors have no task, but may have a live entry.
        let stale: Vec<String> = self
            .live()
            .keys()
            .filter(|id| !wanted.contains_key(id.as_str()))
            .cloned()
            .collect();
        for id in stale {
            self.forget(&id);
            removed += 1;
        }

        let mut persisted = None;
        for m in &new.monitors {
            self.shared.metrics.register_monitor(m);
            let state = match handles.remove(&m.id) {
                Some(h) if same_monitor(&h.config, m) => {
                    handles.insert(m.id.clone(), h);
                    continue;
                }
                Some(h) => {
                    changed += 1;
                    h.stop().await.unwrap_or_else(|| MonitorState::new(now_ms()))
                }
                None => {
                    if persisted.is_none() {
                        persisted = Some(self.store.load_states().await.unwrap_or_default());
                    }
                    let restored = persisted.as_ref().and_then(|p| p.get(&m.id)).map(MonitorState::restore);
                    if m.enabled {
                        added += 1;
                    }
                    restored.unwrap_or_else(|| MonitorState::new(now_ms()))
                }
            };
            if let Some(h) = Self::spawn_monitor(m, state, &self.shared, &self.cancel) {
                handles.insert(m.id.clone(), h);
            }
        }
        drop(handles);

        if let Ok(mut t) = self.push_tokens.write() {
            *t = push_tokens(&new);
        }
        if let Ok(mut c) = self.config.write() {
            *c = new;
        }
        tracing::info!(added, changed, removed, "configuration reloaded");
        Ok(())
    }

    fn forget(&self, id: &str) {
        if let Ok(mut live) = self.shared.live.write() {
            live.remove(id);
        }
        self.shared.metrics.remove_monitor(id);
    }

    async fn send(&self, id: &str, cmd: Command) -> Result<(), CommandError> {
        let handles = self.monitors.lock().await;
        let Some(h) = handles.get(id) else {
            let known = self.config().monitors.iter().any(|m| m.id == id);
            return Err(if known {
                CommandError::Disabled
            } else {
                CommandError::UnknownMonitor
            });
        };
        h.tx.try_send(cmd).map_err(|_| CommandError::Busy)
    }

    pub async fn run_now(&self, id: &str) -> Result<(), CommandError> {
        self.send(id, Command::RunNow).await
    }

    pub async fn set_paused(&self, id: &str, paused: bool) -> Result<(), CommandError> {
        let (tx, rx) = oneshot::channel();
        self.send(id, Command::Pause(paused, tx)).await?;
        rx.await.map_err(|_| CommandError::Busy)
    }

    /// Deliver a push result; returns the monitor id.
    pub async fn push(&self, token: &str, report: PushReport) -> Result<String, CommandError> {
        let id = self
            .push_tokens
            .read()
            .ok()
            .and_then(|t| t.get(token).cloned())
            .ok_or(CommandError::UnknownMonitor)?;
        self.send(&id, Command::Push(report)).await?;
        Ok(id)
    }

    /// Aggregated status of every group.
    pub fn group_statuses(&self) -> Vec<(String, Status)> {
        let config = self.config();
        let live = self.live();
        group_statuses(&config, &live)
    }

    async fn cleanup_loop(self: Arc<Self>) {
        // Let the first run happen shortly after start, not immediately.
        let mut next = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = tokio::time::sleep_until(next) => {}
            }
            let retention = self.config().retention.clone();
            next = tokio::time::Instant::now() + retention.cleanup_interval.0;
            match self.store.cleanup(&retention, now_ms()).await {
                Ok(s) => tracing::info!(
                    heartbeats = s.heartbeats,
                    rollups = s.rollups,
                    events = s.events,
                    notifications = s.notifications,
                    monitors = s.monitors,
                    "retention cleanup done"
                ),
                Err(e) => tracing::error!(error = %format!("{e:#}"), "retention cleanup failed"),
            }
        }
    }

    async fn group_metrics_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = tick.tick() => self.shared.metrics.set_groups(&self.group_statuses()),
            }
        }
    }

    /// Stop every task and flush pending writes.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let handles: Vec<MonitorHandle> = self.monitors.lock().await.drain().map(|(_, h)| h).collect();
        for h in handles {
            h.stop().await;
        }
        self.shared.writer.flush().await;
        self.writer_cancel.cancel();
        for t in self.background.lock().await.drain(..) {
            let _ = t.await;
        }
        tracing::info!("engine stopped");
    }
}

/// Aggregate member statuses into group statuses (members of subgroups count
/// for their ancestors too). Paused, unknown and maintenance members are
/// ignored; a group whose members are all ignored is `unknown`, or
/// `maintenance` if any member is in maintenance.
pub fn group_statuses(config: &Config, live: &HashMap<String, LiveView>) -> Vec<(String, Status)> {
    let groups: HashMap<&str, &GroupConfig> = config.groups.iter().map(|g| (g.id.as_str(), g)).collect();
    let mut members: HashMap<&str, Vec<Status>> = HashMap::new();
    for m in &config.monitors {
        let status = live.get(&m.id).map(|v| v.status).unwrap_or(Status::Unknown);
        for g in &m.group_path {
            members.entry(g.as_str()).or_default().push(status);
        }
    }
    let mut out = Vec::with_capacity(groups.len());
    for g in &config.groups {
        let statuses = members.get(g.id.as_str()).map(Vec::as_slice).unwrap_or_default();
        out.push((g.id.clone(), aggregate(statuses, g.status_policy)));
    }
    out
}

fn aggregate(statuses: &[Status], policy: GroupStatusPolicy) -> Status {
    let relevant: Vec<Status> = statuses
        .iter()
        .copied()
        .filter(|s| matches!(s, Status::Up | Status::Degraded | Status::Down | Status::Pending))
        .collect();
    if relevant.is_empty() {
        return if statuses.contains(&Status::Maintenance) {
            Status::Maintenance
        } else {
            Status::Unknown
        };
    }
    let down = relevant.iter().filter(|s| **s == Status::Down).count();
    let impaired = relevant.iter().any(|s| matches!(s, Status::Degraded | Status::Pending));
    match policy {
        GroupStatusPolicy::AnyDown if down > 0 => Status::Down,
        GroupStatusPolicy::AllDown if down == relevant.len() => Status::Down,
        GroupStatusPolicy::AllDown if down > 0 => Status::Degraded,
        _ if impaired => Status::Degraded,
        _ => Status::Up,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Status::*;

    #[test]
    fn aggregates_groups() {
        let any = GroupStatusPolicy::AnyDown;
        let all = GroupStatusPolicy::AllDown;
        assert_eq!(aggregate(&[Up, Up], any), Up);
        assert_eq!(aggregate(&[Up, Pending], any), Degraded);
        assert_eq!(aggregate(&[Up, Down], any), Down);
        assert_eq!(aggregate(&[Up, Down], all), Degraded);
        assert_eq!(aggregate(&[Down, Down, Paused], all), Down);
        assert_eq!(aggregate(&[Paused, Maintenance], any), Maintenance);
        assert_eq!(aggregate(&[], any), Unknown);
    }
}
