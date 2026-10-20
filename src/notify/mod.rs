//! Notification dispatch. Monitors enqueue notifications; a background task
//! delivers them to every selected notifier with retries and logs the
//! outcome, so a slow provider never delays checks.

mod providers;

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{Semaphore, mpsc};

use crate::config::{EventKind, NotifierConfig};
use crate::engine::writer::{WriteOp, Writer};
use crate::metrics::Metrics;
use crate::model::{Status, now_ms};
use crate::store::NotificationRecord;

const QUEUE: usize = 1024;
const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(5), Duration::from_secs(30)];

/// Payload handed to providers; also the JSON body of webhook notifications.
#[derive(Clone, Debug, Serialize)]
pub struct Notification {
    pub event: EventKind,
    pub monitor_id: String,
    pub monitor_name: String,
    pub monitor_type: String,
    pub target: String,
    pub group: Option<String>,
    pub tags: Vec<String>,
    pub status: Status,
    pub previous_status: Option<Status>,
    pub message: String,
    /// Milliseconds since the Unix epoch.
    pub timestamp: i64,
    /// Since when the monitor is in `status`.
    pub since: i64,
    pub latency_ms: Option<f64>,
}

impl Notification {
    pub fn title(&self) -> String {
        let label = match self.event {
            EventKind::Down => "DOWN",
            EventKind::Up => "UP",
            EventKind::Degraded => "DEGRADED",
            EventKind::Reminder => "STILL DOWN",
            EventKind::Flapping => "FLAPPING",
            EventKind::Test => "TEST",
        };
        format!("[{label}] {}", self.monitor_name)
    }

    pub fn emoji(&self) -> &'static str {
        match self.event {
            EventKind::Down | EventKind::Reminder => "🔴",
            EventKind::Up => "🟢",
            EventKind::Degraded => "🟠",
            EventKind::Flapping => "🟡",
            EventKind::Test => "🔔",
        }
    }

    pub fn body(&self) -> String {
        let mut s = format!("{} ({})\n{}", self.target, self.monitor_type, self.message);
        if self.event == EventKind::Reminder {
            let mins = (self.timestamp - self.since).max(0) / 60_000;
            s.push_str(&format!("\nDown for {}", human_minutes(mins)));
        }
        if let Ok(t) = jiff::Timestamp::from_millisecond(self.timestamp) {
            s.push_str(&format!("\n{}", t.strftime("%Y-%m-%d %H:%M:%S UTC")));
        }
        s
    }

    pub fn test(notifier: &str) -> Self {
        let now = now_ms();
        Self {
            event: EventKind::Test,
            monitor_id: "pingwarden-test".into(),
            monitor_name: "Pingwarden test".into(),
            monitor_type: "test".into(),
            target: format!("notifier {notifier}"),
            group: None,
            tags: Vec::new(),
            status: Status::Up,
            previous_status: None,
            message: "This is a test notification.".into(),
            timestamp: now,
            since: now,
            latency_ms: None,
        }
    }
}

fn human_minutes(mins: i64) -> String {
    match mins {
        m if m < 60 => format!("{m} min"),
        m if m < 1440 => format!("{}h{:02}", m / 60, m % 60),
        m => format!("{}d {}h", m / 1440, (m % 1440) / 60),
    }
}

struct Job {
    notification: Arc<Notification>,
    notifiers: Vec<String>,
}

#[derive(Clone)]
pub struct Dispatcher {
    tx: mpsc::Sender<Job>,
    inner: Arc<Inner>,
}

struct Inner {
    notifiers: RwLock<Arc<BTreeMap<String, NotifierConfig>>>,
    http: reqwest::Client,
    writer: Writer,
    metrics: Metrics,
}

impl Dispatcher {
    pub fn spawn(
        notifiers: BTreeMap<String, NotifierConfig>,
        writer: Writer,
        metrics: Metrics,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("Pingwarden/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(20))
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(1)
            .build()?;
        let inner = Arc::new(Inner {
            notifiers: RwLock::new(Arc::new(notifiers)),
            http,
            writer,
            metrics,
        });
        let (tx, mut rx) = mpsc::channel::<Job>(QUEUE);
        let worker = inner.clone();
        tokio::spawn(async move {
            let limit = Arc::new(Semaphore::new(8));
            loop {
                let job = tokio::select! {
                    job = rx.recv() => match job { Some(j) => j, None => break },
                    _ = shutdown.cancelled() => break,
                };
                let current = worker.current();
                for id in &job.notifiers {
                    let Some(cfg) = current.get(id).cloned() else {
                        tracing::warn!(notifier = %id, "unknown notifier");
                        continue;
                    };
                    if cfg
                        .events
                        .as_ref()
                        .is_some_and(|e| !e.contains(&job.notification.event))
                    {
                        continue;
                    }
                    let Ok(permit) = limit.clone().acquire_owned().await else {
                        break;
                    };
                    let worker = worker.clone();
                    let n = job.notification.clone();
                    tokio::spawn(async move {
                        let _ = worker.deliver(&cfg, &n, true).await;
                        drop(permit);
                    });
                }
            }
        });
        Ok(Self { tx, inner })
    }

    pub fn replace_notifiers(&self, notifiers: BTreeMap<String, NotifierConfig>) {
        if let Ok(mut n) = self.inner.notifiers.write() {
            *n = Arc::new(notifiers);
        }
    }

    pub fn send(&self, notification: Notification, notifiers: Vec<String>) {
        if notifiers.is_empty() {
            return;
        }
        let job = Job {
            notification: Arc::new(notification),
            notifiers,
        };
        if self.tx.try_send(job).is_err() {
            tracing::error!("notification queue is full; notification dropped");
            self.inner.metrics.notification_result("<queue>", false);
        }
    }

    /// Deliver a test notification now and report the outcome.
    pub async fn test(&self, notifier: &str) -> Result<(), String> {
        let cfg = self
            .inner
            .current()
            .get(notifier)
            .cloned()
            .ok_or_else(|| format!("unknown notifier `{notifier}`"))?;
        let n = Notification::test(notifier);
        self.inner.deliver(&cfg, &n, false).await
    }
}

impl Inner {
    fn current(&self) -> Arc<BTreeMap<String, NotifierConfig>> {
        self.notifiers.read().map(|n| n.clone()).unwrap_or_default()
    }

    async fn deliver(&self, cfg: &NotifierConfig, n: &Notification, retry: bool) -> Result<(), String> {
        let attempts = if retry { RETRY_DELAYS.len() + 1 } else { 1 };
        let mut last = String::new();
        for attempt in 0..attempts {
            if attempt > 0 {
                tokio::time::sleep(RETRY_DELAYS[attempt - 1]).await;
            }
            match providers::send(&self.http, &cfg.kind, n).await {
                Ok(()) => {
                    tracing::info!(notifier = %cfg.id, monitor = %n.monitor_id, event = n.event.as_str(), "notification sent");
                    self.record(cfg, n, None);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(notifier = %cfg.id, monitor = %n.monitor_id, attempt = attempt + 1, error = %e, "notification failed");
                    last = e;
                }
            }
        }
        self.record(cfg, n, Some(last.clone()));
        Err(last)
    }

    fn record(&self, cfg: &NotifierConfig, n: &Notification, error: Option<String>) {
        self.metrics.notification_result(&cfg.id, error.is_none());
        self.writer.send(WriteOp::Notification(NotificationRecord {
            ts: now_ms(),
            monitor_id: (n.event != EventKind::Test).then(|| n.monitor_id.clone()),
            notifier: cfg.id.clone(),
            event: n.event.as_str().to_owned(),
            success: error.is_none(),
            error,
        }));
    }
}
