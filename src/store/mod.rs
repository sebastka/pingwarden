//! Persistence on PostgreSQL or MariaDB through sqlx's `Any` driver.
//!
//! Queries are written once with `?` placeholders, which are rewritten to
//! `$n` for PostgreSQL. Only the few statements whose syntax differs (upserts,
//! chunked deletes, advisory locks) are written per dialect. Timestamps are
//! BIGINT milliseconds, so no date type crosses the driver boundary.

use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::any::{AnyConnectOptions, AnyPoolOptions, AnyRow};
use sqlx::{AnyConnection, AnyPool, AssertSqlSafe, Connection, Row};

use crate::config::{DatabaseConfig, RetentionConfig};
use crate::model::Status;

static PG_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");
static MYSQL_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/mysql");

/// Hour and day rollup resolutions, in seconds.
pub const RESOLUTIONS: [i32; 2] = [3600, 86_400];
const MESSAGE_MAX: usize = 1024;
const INSERT_CHUNK: usize = 200;
const DELETE_CHUNK: i64 = 5000;
/// How long ended runtime maintenance windows are kept (and listed).
pub const WINDOW_KEEP_MS: i64 = 7 * 86_400_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    MySql,
}

#[derive(Clone)]
pub struct Store {
    pool: AnyPool,
    dialect: Dialect,
}

#[derive(Clone, Debug)]
pub struct MonitorMeta {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub target: String,
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PersistedState {
    pub status: Status,
    pub since: i64,
    pub notified_status: Option<Status>,
    pub last_notified_at: Option<i64>,
    pub paused: bool,
    pub ack: Option<Acknowledgement>,
    pub silence: Option<Silence>,
}

/// An outage acknowledged through the API: no reminders until it is over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Acknowledgement {
    /// Principal, e.g. `oidc:alice`.
    pub by: String,
    pub at: i64,
    pub comment: Option<String>,
}

/// Notifications about a monitor muted through the API until `until`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Silence {
    pub until: i64,
    pub by: String,
}

/// A maintenance window created through the API.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct RuntimeWindow {
    pub id: String,
    pub description: Option<String>,
    pub selection: WindowSelection,
    pub start_ms: i64,
    pub end_ms: i64,
    pub created_by: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct WindowSelection {
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub monitors: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Filters of the notification log.
#[derive(Clone, Debug, Default)]
pub struct NotificationFilter {
    pub monitor: Option<String>,
    pub notifier: Option<String>,
    pub success: Option<bool>,
    pub event: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Heartbeat {
    pub monitor_id: String,
    pub ts: i64,
    pub status: Status,
    pub latency_us: Option<i64>,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct EventRecord {
    pub monitor_id: String,
    pub ts: i64,
    pub from: Option<Status>,
    pub to: Status,
    pub message: String,
    pub suppressed_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NotificationRecord {
    pub ts: i64,
    pub monitor_id: Option<String>,
    pub notifier: String,
    pub event: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatRow {
    pub ts: i64,
    pub status: Status,
    pub latency_ms: Option<f64>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventRow {
    pub id: i64,
    pub monitor_id: String,
    pub ts: i64,
    pub from: Option<Status>,
    pub to: Status,
    pub message: Option<String>,
    pub suppressed_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NotificationRow {
    pub id: i64,
    pub ts: i64,
    pub monitor_id: Option<String>,
    pub notifier: String,
    pub event: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct Rollup {
    pub bucket: i64,
    pub up: i64,
    pub degraded: i64,
    pub down: i64,
    pub maintenance: i64,
    pub latency_sum_us: i64,
    pub latency_count: i64,
    pub latency_min_us: Option<i64>,
    pub latency_max_us: Option<i64>,
}

impl Rollup {
    fn add(&mut self, status: Status, latency_us: Option<i64>) {
        match status {
            Status::Up => self.up += 1,
            Status::Degraded => self.degraded += 1,
            Status::Down => self.down += 1,
            Status::Maintenance => self.maintenance += 1,
            _ => return,
        }
        if let Some(l) = latency_us
            && status != Status::Maintenance
        {
            self.latency_sum_us += l;
            self.latency_count += 1;
            self.latency_min_us = Some(self.latency_min_us.map_or(l, |m| m.min(l)));
            self.latency_max_us = Some(self.latency_max_us.map_or(l, |m| m.max(l)));
        }
    }

    pub fn merge(&mut self, o: &Rollup) {
        self.up += o.up;
        self.degraded += o.degraded;
        self.down += o.down;
        self.maintenance += o.maintenance;
        self.latency_sum_us += o.latency_sum_us;
        self.latency_count += o.latency_count;
        self.latency_min_us = match (self.latency_min_us, o.latency_min_us) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.latency_max_us = match (self.latency_max_us, o.latency_max_us) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }
}

#[derive(Debug, Default)]
pub struct CleanupStats {
    pub heartbeats: u64,
    pub rollups: u64,
    pub events: u64,
    pub notifications: u64,
    pub monitors: u64,
    pub windows: u64,
}

/// Rewrite `?` placeholders as `$1`, `$2`… (queries contain no `?` literal).
fn to_postgres(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 16);
    let mut n = 0;
    for c in sql.chars() {
        if c == '?' {
            n += 1;
            out.push('$');
            out.push_str(&n.to_string());
        } else {
            out.push(c);
        }
    }
    out
}

fn truncate(s: &str) -> String {
    if s.len() <= MESSAGE_MAX {
        return s.to_owned();
    }
    let mut end = MESSAGE_MAX - 3;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

fn opt_status(code: Option<i16>) -> Option<Status> {
    code.map(Status::from_code)
}

impl Store {
    pub async fn connect(cfg: &DatabaseConfig) -> anyhow::Result<Self> {
        sqlx::any::install_default_drivers();
        let (dialect, url) = parse_url(&cfg.url)?;
        let options: AnyConnectOptions = url.parse().context("invalid database url")?;
        let pool = AnyPoolOptions::new()
            .max_connections(cfg.max_connections.max(2))
            .min_connections(0)
            .acquire_timeout(cfg.connect_timeout.0)
            .idle_timeout(Some(Duration::from_secs(300)))
            .connect_with(options)
            .await
            .context("cannot connect to the database")?;
        Ok(Self { pool, dialect })
    }

    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    fn sql(&self, s: &'static str) -> AssertSqlSafe<Cow<'static, str>> {
        AssertSqlSafe(match self.dialect {
            Dialect::MySql => Cow::Borrowed(s),
            Dialect::Postgres => Cow::Owned(to_postgres(s)),
        })
    }

    fn sql_owned(&self, s: String) -> AssertSqlSafe<Cow<'static, str>> {
        AssertSqlSafe(match self.dialect {
            Dialect::MySql => Cow::Owned(s),
            Dialect::Postgres => Cow::Owned(to_postgres(&s)),
        })
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        let migrator = match self.dialect {
            Dialect::Postgres => &PG_MIGRATIONS,
            Dialect::MySql => &MYSQL_MIGRATIONS,
        };
        migrator.run(&self.pool).await.context("database migration failed")
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query(self.sql("SELECT 1")).execute(&self.pool).await?;
        Ok(())
    }

    // ------------------------------------------------------------ monitors

    /// Register the configured monitors and flag the others as removed.
    pub async fn sync_monitors(&self, monitors: &[MonitorMeta], now: i64) -> anyhow::Result<()> {
        let upsert: &'static str = match self.dialect {
            Dialect::Postgres => {
                "INSERT INTO monitors (id, name, kind, target, description, created_at, updated_at, removed_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, NULL) ON CONFLICT (id) DO UPDATE SET \
                 name = EXCLUDED.name, kind = EXCLUDED.kind, target = EXCLUDED.target, \
                 description = EXCLUDED.description, updated_at = EXCLUDED.updated_at, removed_at = NULL"
            }
            Dialect::MySql => {
                "INSERT INTO monitors (id, name, kind, target, description, created_at, updated_at, removed_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, NULL) ON DUPLICATE KEY UPDATE \
                 name = VALUES(name), kind = VALUES(kind), target = VALUES(target), \
                 description = VALUES(description), updated_at = VALUES(updated_at), removed_at = NULL"
            }
        };
        let mut tx = self.pool.begin().await?;
        for m in monitors {
            sqlx::query(self.sql(upsert))
                .bind(&m.id)
                .bind(&m.name)
                .bind(&m.kind)
                .bind(&m.target)
                .bind(m.description.clone())
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("cannot register monitor {}", m.id))?;
        }
        let active: Vec<String> = sqlx::query(self.sql("SELECT id FROM monitors WHERE removed_at IS NULL"))
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(|r| r.try_get::<String, _>(0))
            .collect::<Result<_, _>>()?;
        for id in active {
            if !monitors.iter().any(|m| m.id == id) {
                sqlx::query(self.sql("UPDATE monitors SET removed_at = ? WHERE id = ?"))
                    .bind(now)
                    .bind(&id)
                    .execute(&mut *tx)
                    .await?;
                tracing::info!(monitor = %id, "monitor removed from configuration; history kept until retention.removed_monitors");
            }
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn load_states(&self) -> anyhow::Result<HashMap<String, PersistedState>> {
        let rows = sqlx::query(self.sql(
            "SELECT monitor_id, status, since, notified_status, last_notified_at, paused, \
             ack_by, ack_at, ack_comment, silenced_until, silenced_by FROM monitor_state",
        ))
        .fetch_all(&self.pool)
        .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for r in rows {
            let ack = match (r.try_get::<Option<String>, _>(6)?, r.try_get::<Option<i64>, _>(7)?) {
                (Some(by), Some(at)) => Some(Acknowledgement {
                    by,
                    at,
                    comment: r.try_get(8)?,
                }),
                _ => None,
            };
            let silence = match (r.try_get::<Option<i64>, _>(9)?, r.try_get::<Option<String>, _>(10)?) {
                (Some(until), Some(by)) => Some(Silence { until, by }),
                _ => None,
            };
            out.insert(
                r.try_get::<String, _>(0)?,
                PersistedState {
                    status: Status::from_code(r.try_get(1)?),
                    since: r.try_get(2)?,
                    notified_status: opt_status(r.try_get(3)?),
                    last_notified_at: r.try_get(4)?,
                    paused: r.try_get::<i16, _>(5)? != 0,
                    ack,
                    silence,
                },
            );
        }
        Ok(out)
    }

    pub async fn save_state(&self, monitor_id: &str, s: &PersistedState, now: i64) -> anyhow::Result<()> {
        let q = match self.dialect {
            Dialect::Postgres => self.sql(
                "INSERT INTO monitor_state (monitor_id, status, since, notified_status, last_notified_at, paused, \
                 ack_by, ack_at, ack_comment, silenced_until, silenced_by, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (monitor_id) DO UPDATE SET \
                 status = EXCLUDED.status, since = EXCLUDED.since, notified_status = EXCLUDED.notified_status, \
                 last_notified_at = EXCLUDED.last_notified_at, paused = EXCLUDED.paused, \
                 ack_by = EXCLUDED.ack_by, ack_at = EXCLUDED.ack_at, ack_comment = EXCLUDED.ack_comment, \
                 silenced_until = EXCLUDED.silenced_until, silenced_by = EXCLUDED.silenced_by, \
                 updated_at = EXCLUDED.updated_at",
            ),
            Dialect::MySql => self.sql(
                "INSERT INTO monitor_state (monitor_id, status, since, notified_status, last_notified_at, paused, \
                 ack_by, ack_at, ack_comment, silenced_until, silenced_by, updated_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE \
                 status = VALUES(status), since = VALUES(since), notified_status = VALUES(notified_status), \
                 last_notified_at = VALUES(last_notified_at), paused = VALUES(paused), \
                 ack_by = VALUES(ack_by), ack_at = VALUES(ack_at), ack_comment = VALUES(ack_comment), \
                 silenced_until = VALUES(silenced_until), silenced_by = VALUES(silenced_by), \
                 updated_at = VALUES(updated_at)",
            ),
        };
        sqlx::query(q)
            .bind(monitor_id)
            .bind(s.status.code())
            .bind(s.since)
            .bind(s.notified_status.map(Status::code))
            .bind(s.last_notified_at)
            .bind(i16::from(s.paused))
            .bind(s.ack.as_ref().map(|a| a.by.clone()))
            .bind(s.ack.as_ref().map(|a| a.at))
            .bind(s.ack.as_ref().and_then(|a| a.comment.clone()))
            .bind(s.silence.as_ref().map(|x| x.until))
            .bind(s.silence.as_ref().map(|x| x.by.clone()))
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---------------------------------------------------------- heartbeats

    /// Insert heartbeats and fold them into the hourly and daily rollups, atomically.
    pub async fn insert_heartbeats(&self, batch: &[Heartbeat]) -> anyhow::Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut rollups: HashMap<(&str, i32, i64), Rollup> = HashMap::new();
        for hb in batch {
            for res in RESOLUTIONS {
                let size = i64::from(res) * 1000;
                let bucket = hb.ts.div_euclid(size) * size;
                rollups
                    .entry((hb.monitor_id.as_str(), res, bucket))
                    .or_insert_with(|| Rollup {
                        bucket,
                        ..Rollup::default()
                    })
                    .add(hb.status, hb.latency_us);
            }
        }
        let mut tx = self.pool.begin().await?;
        for chunk in batch.chunks(INSERT_CHUNK) {
            let mut sql = String::from("INSERT INTO heartbeats (monitor_id, ts, status, latency_us, message) VALUES ");
            for i in 0..chunk.len() {
                sql.push_str(if i == 0 { "(?, ?, ?, ?, ?)" } else { ", (?, ?, ?, ?, ?)" });
            }
            let mut q = sqlx::query(self.sql_owned(sql));
            for hb in chunk {
                q = q
                    .bind(hb.monitor_id.clone())
                    .bind(hb.ts)
                    .bind(hb.status.code())
                    .bind(hb.latency_us)
                    .bind(truncate(&hb.message));
            }
            q.execute(&mut *tx).await?;
        }
        let rollups: Vec<_> = rollups.into_iter().collect();
        for chunk in rollups.chunks(INSERT_CHUNK) {
            let mut sql = String::from(
                "INSERT INTO rollups (monitor_id, resolution, bucket, up_count, degraded_count, down_count, \
                 maintenance_count, latency_sum_us, latency_count, latency_min_us, latency_max_us) VALUES ",
            );
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push_str(", ");
                }
                sql.push_str("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            }
            sql.push_str(match self.dialect {
                Dialect::Postgres => {
                    " ON CONFLICT (monitor_id, resolution, bucket) DO UPDATE SET \
                     up_count = rollups.up_count + EXCLUDED.up_count, \
                     degraded_count = rollups.degraded_count + EXCLUDED.degraded_count, \
                     down_count = rollups.down_count + EXCLUDED.down_count, \
                     maintenance_count = rollups.maintenance_count + EXCLUDED.maintenance_count, \
                     latency_sum_us = rollups.latency_sum_us + EXCLUDED.latency_sum_us, \
                     latency_count = rollups.latency_count + EXCLUDED.latency_count, \
                     latency_min_us = LEAST(rollups.latency_min_us, EXCLUDED.latency_min_us), \
                     latency_max_us = GREATEST(rollups.latency_max_us, EXCLUDED.latency_max_us)"
                }
                Dialect::MySql => {
                    " ON DUPLICATE KEY UPDATE \
                     up_count = up_count + VALUES(up_count), \
                     degraded_count = degraded_count + VALUES(degraded_count), \
                     down_count = down_count + VALUES(down_count), \
                     maintenance_count = maintenance_count + VALUES(maintenance_count), \
                     latency_sum_us = latency_sum_us + VALUES(latency_sum_us), \
                     latency_count = latency_count + VALUES(latency_count), \
                     latency_min_us = COALESCE(LEAST(latency_min_us, VALUES(latency_min_us)), latency_min_us, VALUES(latency_min_us)), \
                     latency_max_us = COALESCE(GREATEST(latency_max_us, VALUES(latency_max_us)), latency_max_us, VALUES(latency_max_us))"
                }
            });
            let mut q = sqlx::query(self.sql_owned(sql));
            for ((monitor, res, _), r) in chunk {
                q = q
                    .bind((*monitor).to_owned())
                    .bind(*res)
                    .bind(r.bucket)
                    .bind(r.up)
                    .bind(r.degraded)
                    .bind(r.down)
                    .bind(r.maintenance)
                    .bind(r.latency_sum_us)
                    .bind(r.latency_count)
                    .bind(r.latency_min_us)
                    .bind(r.latency_max_us);
            }
            q.execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Insert an event and return it as the API lists it (with its id).
    pub async fn insert_event(&self, e: &EventRecord) -> anyhow::Result<EventRow> {
        let message = truncate(&e.message);
        let q = match self.dialect {
            Dialect::Postgres => self.sql(
                "INSERT INTO events (monitor_id, ts, from_status, to_status, message, suppressed_reason) \
                 VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
            ),
            Dialect::MySql => self.sql(
                "INSERT INTO events (monitor_id, ts, from_status, to_status, message, suppressed_reason) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            ),
        };
        let q = sqlx::query(q)
            .bind(&e.monitor_id)
            .bind(e.ts)
            .bind(e.from.map(Status::code))
            .bind(e.to.code())
            .bind(message.clone())
            .bind(e.suppressed_reason.clone());
        let id = self.insert_returning_id(q).await?;
        Ok(EventRow {
            id,
            monitor_id: e.monitor_id.clone(),
            ts: e.ts,
            from: e.from,
            to: e.to,
            message: Some(message),
            suppressed_reason: e.suppressed_reason.clone(),
        })
    }

    /// Insert a delivery record and return it as the API lists it (with its id).
    pub async fn insert_notification(&self, n: &NotificationRecord) -> anyhow::Result<NotificationRow> {
        let error = n.error.as_deref().map(truncate);
        let q = match self.dialect {
            Dialect::Postgres => self.sql(
                "INSERT INTO notifications (ts, monitor_id, notifier, event, success, error) \
                 VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
            ),
            Dialect::MySql => self.sql(
                "INSERT INTO notifications (ts, monitor_id, notifier, event, success, error) VALUES (?, ?, ?, ?, ?, ?)",
            ),
        };
        let q = sqlx::query(q)
            .bind(n.ts)
            .bind(n.monitor_id.clone())
            .bind(&n.notifier)
            .bind(&n.event)
            .bind(i16::from(n.success))
            .bind(error.clone());
        let id = self.insert_returning_id(q).await?;
        Ok(NotificationRow {
            id,
            ts: n.ts,
            monitor_id: n.monitor_id.clone(),
            notifier: n.notifier.clone(),
            event: n.event.clone(),
            success: n.success,
            error,
        })
    }

    /// Run an INSERT and return the generated id: `RETURNING id` on
    /// PostgreSQL, the last insert id on MariaDB.
    async fn insert_returning_id(
        &self,
        q: sqlx::query::Query<'_, sqlx::Any, sqlx::any::AnyArguments>,
    ) -> anyhow::Result<i64> {
        match self.dialect {
            Dialect::Postgres => Ok(q.fetch_one(&self.pool).await?.try_get::<i64, _>(0)?),
            Dialect::MySql => q
                .execute(&self.pool)
                .await?
                .last_insert_id()
                .context("the database returned no insert id"),
        }
    }

    // -------------------------------------------------------------- reads

    pub async fn heartbeats(
        &self,
        monitor_id: &str,
        from: i64,
        to: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<HeartbeatRow>> {
        let rows = sqlx::query(self.sql(
            "SELECT ts, status, latency_us, message FROM heartbeats \
             WHERE monitor_id = ? AND ts >= ? AND ts < ? ORDER BY ts DESC LIMIT ?",
        ))
        .bind(monitor_id)
        .bind(from)
        .bind(to)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(HeartbeatRow {
                    ts: r.try_get(0)?,
                    status: Status::from_code(r.try_get(1)?),
                    latency_ms: r.try_get::<Option<i64>, _>(2)?.map(|us| us as f64 / 1000.0),
                    message: r.try_get(3)?,
                })
            })
            .collect()
    }

    pub async fn events(
        &self,
        monitor_id: Option<&str>,
        from: i64,
        to: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<EventRow>> {
        let rows = match monitor_id {
            Some(id) => sqlx::query(self.sql(
                "SELECT id, monitor_id, ts, from_status, to_status, message, suppressed_reason FROM events \
                 WHERE monitor_id = ? AND ts >= ? AND ts < ? ORDER BY ts DESC, id DESC LIMIT ?",
            ))
            .bind(id),
            None => sqlx::query(self.sql(
                "SELECT id, monitor_id, ts, from_status, to_status, message, suppressed_reason FROM events \
                 WHERE ts >= ? AND ts < ? ORDER BY ts DESC, id DESC LIMIT ?",
            )),
        }
        .bind(from)
        .bind(to)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(event_row).collect()
    }

    pub async fn notifications(
        &self,
        filter: &NotificationFilter,
        from: i64,
        to: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<NotificationRow>> {
        let mut sql = String::from(
            "SELECT id, ts, monitor_id, notifier, event, success, error FROM notifications WHERE ts >= ? AND ts < ?",
        );
        for (cond, set) in [
            (" AND monitor_id = ?", filter.monitor.is_some()),
            (" AND notifier = ?", filter.notifier.is_some()),
            (" AND success = ?", filter.success.is_some()),
            (" AND event = ?", filter.event.is_some()),
        ] {
            if set {
                sql.push_str(cond);
            }
        }
        sql.push_str(" ORDER BY ts DESC, id DESC LIMIT ?");
        let mut q = sqlx::query(self.sql_owned(sql)).bind(from).bind(to);
        if let Some(m) = &filter.monitor {
            q = q.bind(m.clone());
        }
        if let Some(n) = &filter.notifier {
            q = q.bind(n.clone());
        }
        if let Some(ok) = filter.success {
            q = q.bind(i16::from(ok));
        }
        if let Some(e) = &filter.event {
            q = q.bind(e.clone());
        }
        let rows = q.bind(limit).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|r| {
                Ok(NotificationRow {
                    id: r.try_get(0)?,
                    ts: r.try_get(1)?,
                    monitor_id: r.try_get(2)?,
                    notifier: r.try_get(3)?,
                    event: r.try_get(4)?,
                    success: r.try_get::<i16, _>(5)? != 0,
                    error: r.try_get(6)?,
                })
            })
            .collect()
    }

    pub async fn rollups(&self, monitor_id: &str, resolution: i32, from: i64, to: i64) -> anyhow::Result<Vec<Rollup>> {
        let rows = sqlx::query(self.sql(
            "SELECT bucket, up_count, degraded_count, down_count, maintenance_count, latency_sum_us, \
             latency_count, latency_min_us, latency_max_us FROM rollups \
             WHERE monitor_id = ? AND resolution = ? AND bucket >= ? AND bucket < ? ORDER BY bucket",
        ))
        .bind(monitor_id)
        .bind(resolution)
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Rollup {
                    bucket: r.try_get(0)?,
                    up: r.try_get(1)?,
                    degraded: r.try_get(2)?,
                    down: r.try_get(3)?,
                    maintenance: r.try_get(4)?,
                    latency_sum_us: r.try_get(5)?,
                    latency_count: r.try_get(6)?,
                    latency_min_us: r.try_get(7)?,
                    latency_max_us: r.try_get(8)?,
                })
            })
            .collect()
    }

    /// Rollups of every monitor at one resolution, in one query, by monitor.
    pub async fn rollups_all(
        &self,
        resolution: i32,
        from: i64,
        to: i64,
    ) -> anyhow::Result<HashMap<String, Vec<Rollup>>> {
        let rows = sqlx::query(self.sql(
            "SELECT monitor_id, bucket, up_count, degraded_count, down_count, maintenance_count, latency_sum_us, \
             latency_count, latency_min_us, latency_max_us FROM rollups \
             WHERE resolution = ? AND bucket >= ? AND bucket < ? ORDER BY monitor_id, bucket",
        ))
        .bind(resolution)
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        let mut out: HashMap<String, Vec<Rollup>> = HashMap::new();
        for r in rows {
            out.entry(r.try_get(0)?).or_default().push(Rollup {
                bucket: r.try_get(1)?,
                up: r.try_get(2)?,
                degraded: r.try_get(3)?,
                down: r.try_get(4)?,
                maintenance: r.try_get(5)?,
                latency_sum_us: r.try_get(6)?,
                latency_count: r.try_get(7)?,
                latency_min_us: r.try_get(8)?,
                latency_max_us: r.try_get(9)?,
            });
        }
        Ok(out)
    }

    // ---------------------------------------------- runtime maintenance

    pub async fn insert_window(&self, w: &RuntimeWindow) -> anyhow::Result<()> {
        sqlx::query(self.sql(
            "INSERT INTO maintenance_windows (id, description, selection, start_ms, end_ms, created_by, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(&w.id)
        .bind(w.description.clone())
        .bind(serde_json::to_string(&w.selection)?)
        .bind(w.start_ms)
        .bind(w.end_ms)
        .bind(&w.created_by)
        .bind(w.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Runtime windows ending at or after `ended_after`, by start.
    pub async fn load_windows(&self, ended_after: i64) -> anyhow::Result<Vec<RuntimeWindow>> {
        let rows = sqlx::query(self.sql(
            "SELECT id, description, selection, start_ms, end_ms, created_by, created_at FROM maintenance_windows \
             WHERE end_ms >= ? ORDER BY start_ms, id",
        ))
        .bind(ended_after)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(RuntimeWindow {
                    id: r.try_get(0)?,
                    description: r.try_get(1)?,
                    selection: serde_json::from_str(&r.try_get::<String, _>(2)?).context("invalid window selection")?,
                    start_ms: r.try_get(3)?,
                    end_ms: r.try_get(4)?,
                    created_by: r.try_get(5)?,
                    created_at: r.try_get(6)?,
                })
            })
            .collect()
    }

    /// Whether a runtime window with this id exists (ended ones included, until purged).
    pub async fn window_exists(&self, id: &str) -> anyhow::Result<bool> {
        let row = sqlx::query(self.sql("SELECT COUNT(*) FROM maintenance_windows WHERE id = ?"))
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get::<i64, _>(0)? > 0)
    }

    /// End a window: its end becomes `end_ms` unless it already ended earlier.
    pub async fn end_window(&self, id: &str, end_ms: i64) -> anyhow::Result<()> {
        sqlx::query(self.sql("UPDATE maintenance_windows SET end_ms = ? WHERE id = ? AND end_ms > ?"))
            .bind(end_ms)
            .bind(id)
            .bind(end_ms)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ------------------------------------------------------------ cleanup

    pub async fn cleanup(&self, r: &RetentionConfig, now: i64) -> anyhow::Result<CleanupStats> {
        let cutoff = |d: crate::config::Dur| (!d.is_zero()).then(|| now - d.as_millis_i64());
        let mut stats = CleanupStats::default();
        if let Some(c) = cutoff(r.heartbeats) {
            stats.heartbeats = self.delete_chunked("heartbeats", c).await?;
        }
        if let Some(c) = cutoff(r.events) {
            stats.events = self.delete_chunked("events", c).await?;
        }
        if let Some(c) = cutoff(r.notifications) {
            stats.notifications = self.delete_chunked("notifications", c).await?;
        }
        for (res, keep) in [(3600, r.hourly), (86_400, r.daily)] {
            if let Some(c) = cutoff(keep) {
                stats.rollups += sqlx::query(self.sql("DELETE FROM rollups WHERE resolution = ? AND bucket < ?"))
                    .bind(res)
                    .bind(c)
                    .execute(&self.pool)
                    .await?
                    .rows_affected();
            }
        }
        // Ended runtime maintenance windows are listed for a week, then purged.
        stats.windows = sqlx::query(self.sql("DELETE FROM maintenance_windows WHERE end_ms < ?"))
            .bind(now - WINDOW_KEEP_MS)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if let Some(c) = cutoff(r.removed_monitors) {
            let gone: Vec<String> =
                sqlx::query(self.sql("SELECT id FROM monitors WHERE removed_at IS NOT NULL AND removed_at < ?"))
                    .bind(c)
                    .fetch_all(&self.pool)
                    .await?
                    .iter()
                    .map(|r| r.try_get::<String, _>(0))
                    .collect::<Result<_, _>>()?;
            for id in gone {
                for table in ["heartbeats", "rollups", "events"] {
                    let sql = format!("DELETE FROM {table} WHERE monitor_id = ?");
                    sqlx::query(self.sql_owned(sql)).bind(&id).execute(&self.pool).await?;
                }
                sqlx::query(self.sql("DELETE FROM monitors WHERE id = ?"))
                    .bind(&id)
                    .execute(&self.pool)
                    .await?;
                stats.monitors += 1;
            }
        }
        Ok(stats)
    }

    /// Delete rows older than `cutoff` in small batches to keep locks short.
    async fn delete_chunked(&self, table: &'static str, cutoff: i64) -> anyhow::Result<u64> {
        let sql = match self.dialect {
            Dialect::Postgres => {
                format!("DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE ts < ? LIMIT ?)")
            }
            Dialect::MySql => format!("DELETE FROM {table} WHERE ts < ? LIMIT ?"),
        };
        let mut total = 0;
        loop {
            let n = sqlx::query(self.sql_owned(sql.clone()))
                .bind(cutoff)
                .bind(DELETE_CHUNK)
                .execute(&self.pool)
                .await?
                .rows_affected();
            total += n;
            if n < DELETE_CHUNK as u64 {
                return Ok(total);
            }
            tokio::task::yield_now().await;
        }
    }

    // --------------------------------------------------------- leadership

    /// Try to take the session-scoped advisory lock electing the active instance.
    pub async fn try_lock(&self, name: &str) -> anyhow::Result<Option<LeaderLock>> {
        let mut conn = self.pool.acquire().await?.detach();
        let acquired = match self.dialect {
            Dialect::Postgres => sqlx::query(self.sql("SELECT pg_try_advisory_lock(?)"))
                .bind(lock_key(name))
                .fetch_one(&mut conn)
                .await?
                .try_get::<bool, _>(0)?,
            Dialect::MySql => {
                sqlx::query(self.sql("SELECT GET_LOCK(?, 0)"))
                    .bind(mysql_lock_name(name))
                    .fetch_one(&mut conn)
                    .await?
                    .try_get::<Option<i64>, _>(0)?
                    == Some(1)
            }
        };
        if acquired {
            Ok(Some(LeaderLock {
                conn,
                dialect: self.dialect,
                name: name.to_owned(),
            }))
        } else {
            let _ = conn.close().await;
            Ok(None)
        }
    }
}

fn event_row(r: &AnyRow) -> anyhow::Result<EventRow> {
    Ok(EventRow {
        id: r.try_get(0)?,
        monitor_id: r.try_get(1)?,
        ts: r.try_get(2)?,
        from: opt_status(r.try_get(3)?),
        to: Status::from_code(r.try_get(4)?),
        message: r.try_get(5)?,
        suppressed_reason: r.try_get(6)?,
    })
}

fn parse_url(url: &str) -> anyhow::Result<(Dialect, String)> {
    let scheme = url.split_once("://").map(|(s, _)| s).unwrap_or_default();
    match scheme {
        "postgres" | "postgresql" => Ok((Dialect::Postgres, url.to_owned())),
        "mysql" => Ok((Dialect::MySql, url.to_owned())),
        "mariadb" => Ok((Dialect::MySql, url.replacen("mariadb://", "mysql://", 1))),
        _ => bail!("unsupported database url scheme {scheme:?}: use postgres:// or mariadb:// (mysql://)"),
    }
}

fn lock_key(name: &str) -> i64 {
    let digest = Sha256::digest(name.as_bytes());
    i64::from_be_bytes(digest[..8].try_into().expect("8 bytes"))
}

fn mysql_lock_name(name: &str) -> String {
    // MariaDB lock names are limited to 64 characters.
    name.chars().take(64).collect()
}

/// Held advisory lock. Dropping it without [`LeaderLock::release`] closes
/// the connection, which releases the lock on the server too.
pub struct LeaderLock {
    conn: AnyConnection,
    dialect: Dialect,
    name: String,
}

impl LeaderLock {
    /// Fails when the connection, and therefore the lock, is lost.
    pub async fn check(&mut self) -> anyhow::Result<()> {
        sqlx::query(AssertSqlSafe("SELECT 1")).execute(&mut self.conn).await?;
        Ok(())
    }

    pub async fn release(mut self) {
        let res = match self.dialect {
            Dialect::Postgres => {
                sqlx::query(AssertSqlSafe("SELECT pg_advisory_unlock($1)"))
                    .bind(lock_key(&self.name))
                    .execute(&mut self.conn)
                    .await
            }
            Dialect::MySql => {
                sqlx::query(AssertSqlSafe("SELECT RELEASE_LOCK(?)"))
                    .bind(mysql_lock_name(&self.name))
                    .execute(&mut self.conn)
                    .await
            }
        };
        if let Err(e) = res {
            tracing::debug!(error = %e, "cannot release leader lock");
        }
        let _ = self.conn.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_placeholders() {
        assert_eq!(to_postgres("a = ? AND b IN (?, ?)"), "a = $1 AND b IN ($2, $3)");
    }

    #[test]
    fn parses_urls() {
        assert_eq!(parse_url("postgres://u@h/db").unwrap().0, Dialect::Postgres);
        let (d, u) = parse_url("mariadb://u@h/db").unwrap();
        assert_eq!((d, u.as_str()), (Dialect::MySql, "mysql://u@h/db"));
        assert!(parse_url("sqlite://x").is_err());
    }

    #[test]
    fn truncates_on_char_boundary() {
        let s = "é".repeat(MESSAGE_MAX);
        let t = truncate(&s);
        assert!(t.len() <= MESSAGE_MAX);
        assert!(t.ends_with("..."));
    }

    #[test]
    fn rollup_merges() {
        let mut a = Rollup::default();
        a.add(Status::Up, Some(10));
        a.add(Status::Down, None);
        let mut b = Rollup::default();
        b.add(Status::Degraded, Some(5));
        b.add(Status::Maintenance, Some(1000));
        a.merge(&b);
        assert_eq!((a.up, a.degraded, a.down, a.maintenance), (1, 1, 1, 1));
        assert_eq!(
            (a.latency_count, a.latency_min_us, a.latency_max_us),
            (2, Some(5), Some(10))
        );
    }
}
