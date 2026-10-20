//! Prometheus metrics exposed on `/metrics`.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

use crate::config::MonitorConfig;
use crate::model::{Outcome, Status};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct MonitorLabels {
    monitor: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct InfoLabels {
    monitor: String,
    name: String,
    monitor_type: String,
    group: String,
    /// Comma-separated with leading and trailing commas, for `=~".*,prod,.*"`.
    tags: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct CheckLabels {
    monitor: String,
    outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct GroupLabels {
    group: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct NotifierLabels {
    notifier: String,
    result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildLabels {
    version: String,
}

#[derive(Clone)]
pub struct Metrics(Arc<Inner>);

struct Inner {
    registry: Registry,
    info: Family<InfoLabels, Gauge>,
    status: Family<MonitorLabels, Gauge>,
    up: Family<MonitorLabels, Gauge>,
    latency: Family<MonitorLabels, Gauge<f64, AtomicU64>>,
    checks: Family<CheckLabels, Counter>,
    cert_expiry: Family<MonitorLabels, Gauge>,
    group_status: Family<GroupLabels, Gauge>,
    notifications: Family<NotifierLabels, Counter>,
    dropped: Counter,
    db_errors: Counter,
    leader: Gauge,
    known: Mutex<HashMap<String, InfoLabels>>,
    groups: Mutex<Vec<String>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let mut registry = Registry::with_prefix("pingwarden");
        let info = Family::<InfoLabels, Gauge>::default();
        registry.register("monitor_info", "Monitor metadata (always 1)", info.clone());
        let status = Family::<MonitorLabels, Gauge>::default();
        registry.register(
            "monitor_status",
            "Monitor status: 0 down, 1 up, 2 pending, 3 maintenance, 4 degraded, 5 paused, 6 unknown",
            status.clone(),
        );
        let up = Family::<MonitorLabels, Gauge>::default();
        registry.register("monitor_up", "1 when the monitor is up or degraded, else 0", up.clone());
        let latency = Family::<MonitorLabels, Gauge<f64, AtomicU64>>::default();
        registry.register("monitor_latency_seconds", "Latency of the last check", latency.clone());
        let checks = Family::<CheckLabels, Counter>::default();
        registry.register("monitor_checks", "Checks executed, by outcome", checks.clone());
        let cert_expiry = Family::<MonitorLabels, Gauge>::default();
        registry.register(
            "monitor_cert_expiry_timestamp_seconds",
            "Earliest expiry of the presented certificate chain",
            cert_expiry.clone(),
        );
        let group_status = Family::<GroupLabels, Gauge>::default();
        registry.register(
            "group_status",
            "Aggregated group status (same codes as monitor_status)",
            group_status.clone(),
        );
        let notifications = Family::<NotifierLabels, Counter>::default();
        registry.register(
            "notifications",
            "Notification deliveries, by result",
            notifications.clone(),
        );
        let dropped = Counter::default();
        registry.register(
            "heartbeats_dropped",
            "Results dropped because the database write queue was full",
            dropped.clone(),
        );
        let db_errors = Counter::default();
        registry.register("database_errors", "Failed database writes", db_errors.clone());
        let leader = Gauge::default();
        registry.register("leader", "1 when this instance runs the checks", leader.clone());
        let build = Family::<BuildLabels, Gauge>::default();
        registry.register("build_info", "Build information", build.clone());
        build
            .get_or_create(&BuildLabels {
                version: env!("CARGO_PKG_VERSION").into(),
            })
            .set(1);
        Self(Arc::new(Inner {
            registry,
            info,
            status,
            up,
            latency,
            checks,
            cert_expiry,
            group_status,
            notifications,
            dropped,
            db_errors,
            leader,
            known: Mutex::new(HashMap::new()),
            groups: Mutex::new(Vec::new()),
        }))
    }

    pub fn encode(&self) -> String {
        let mut out = String::new();
        if let Err(e) = prometheus_client::encoding::text::encode(&mut out, &self.0.registry) {
            tracing::error!(error = %e, "cannot encode metrics");
        }
        out
    }

    fn labels(id: &str) -> MonitorLabels {
        MonitorLabels { monitor: id.to_owned() }
    }

    pub fn register_monitor(&self, m: &MonitorConfig) {
        let info = InfoLabels {
            monitor: m.id.clone(),
            name: m.name.clone(),
            monitor_type: m.check.type_name().into(),
            group: m.group.clone().unwrap_or_default(),
            tags: if m.effective_tags.is_empty() {
                String::new()
            } else {
                format!(",{},", m.effective_tags.join(","))
            },
        };
        let Ok(mut known) = self.0.known.lock() else { return };
        if let Some(old) = known.insert(m.id.clone(), info.clone())
            && old != info
        {
            self.0.info.remove(&old);
        }
        self.0.info.get_or_create(&info).set(1);
    }

    pub fn remove_monitor(&self, id: &str) {
        let Ok(mut known) = self.0.known.lock() else { return };
        if let Some(info) = known.remove(id) {
            self.0.info.remove(&info);
        }
        let l = Self::labels(id);
        self.0.status.remove(&l);
        self.0.up.remove(&l);
        self.0.latency.remove(&l);
        self.0.cert_expiry.remove(&l);
        for outcome in [Outcome::Up, Outcome::Degraded, Outcome::Down] {
            self.0.checks.remove(&CheckLabels {
                monitor: id.to_owned(),
                outcome: outcome.as_str().to_owned(),
            });
        }
    }

    pub fn set_status(&self, id: &str, status: Status) {
        let l = Self::labels(id);
        self.0.status.get_or_create(&l).set(i64::from(status.code()));
        self.0.up.get_or_create(&l).set(i64::from(status.is_available()));
    }

    pub fn observe(&self, id: &str, outcome: Outcome, latency_s: Option<f64>, cert_expiry: Option<i64>) {
        let l = Self::labels(id);
        self.0
            .checks
            .get_or_create(&CheckLabels {
                monitor: id.to_owned(),
                outcome: outcome.as_str().to_owned(),
            })
            .inc();
        if let Some(s) = latency_s {
            self.0.latency.get_or_create(&l).set(s);
        }
        if let Some(t) = cert_expiry {
            self.0.cert_expiry.get_or_create(&l).set(t);
        }
    }

    pub fn set_groups(&self, statuses: &[(String, Status)]) {
        let Ok(mut groups) = self.0.groups.lock() else { return };
        for g in groups.iter() {
            if !statuses.iter().any(|(id, _)| id == g) {
                self.0.group_status.remove(&GroupLabels { group: g.clone() });
            }
        }
        *groups = statuses.iter().map(|(id, _)| id.clone()).collect();
        for (id, s) in statuses {
            self.0
                .group_status
                .get_or_create(&GroupLabels { group: id.clone() })
                .set(i64::from(s.code()));
        }
    }

    pub fn notification_result(&self, notifier: &str, success: bool) {
        self.0
            .notifications
            .get_or_create(&NotifierLabels {
                notifier: notifier.to_owned(),
                result: if success { "success" } else { "failure" }.into(),
            })
            .inc();
    }

    pub fn heartbeat_dropped(&self) {
        self.0.dropped.inc();
    }

    pub fn db_error(&self) {
        self.0.db_errors.inc();
    }

    pub fn set_leader(&self, leader: bool) {
        self.0.leader.set(i64::from(leader));
    }
}
