//! One task per monitor: schedules checks, feeds the state machine and turns
//! its effects into writes, metrics and notifications.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::Shared;
use super::state::{Context, Effects, MonitorState, Policy};
use super::writer::WriteOp;
use crate::checks::{Check, CheckResult};
use crate::config::{Dur, MonitorConfig};
use crate::model::{Outcome, Status, now_ms};
use crate::notify::Notification;
use crate::store::{EventRecord, Heartbeat};

pub enum Command {
    RunNow,
    Push(PushReport),
    Pause(bool, oneshot::Sender<()>),
}

pub struct PushReport {
    pub outcome: Outcome,
    pub message: String,
    pub latency: Option<Duration>,
}

pub struct MonitorHandle {
    pub config: Arc<MonitorConfig>,
    pub tx: mpsc::Sender<Command>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<MonitorState>,
}

impl MonitorHandle {
    /// Stop the task and return its state, so a reconfigured monitor keeps it.
    pub async fn stop(self) -> Option<MonitorState> {
        self.cancel.cancel();
        self.task.await.ok()
    }
}

pub fn spawn(
    config: Arc<MonitorConfig>,
    check: Check,
    state: MonitorState,
    shared: Arc<Shared>,
    parent: &CancellationToken,
) -> MonitorHandle {
    let (tx, rx) = mpsc::channel(16);
    let cancel = parent.child_token();
    let policy = Policy {
        failure_threshold: config.failure_threshold,
        recovery_threshold: config.recovery_threshold,
        renotify_every_ms: config.renotify_every.as_millis_i64(),
        notify_degraded: config.notify_degraded,
        flapping: config.flapping,
    };
    let task = MonitorTask {
        config: config.clone(),
        check,
        state,
        policy,
        shared,
        rx,
        cancel: cancel.clone(),
        last_push: Instant::now(),
    };
    MonitorHandle {
        config,
        tx,
        cancel,
        task: tokio::spawn(task.run()),
    }
}

struct MonitorTask {
    config: Arc<MonitorConfig>,
    check: Check,
    state: MonitorState,
    policy: Policy,
    shared: Arc<Shared>,
    rx: mpsc::Receiver<Command>,
    cancel: CancellationToken,
    last_push: Instant,
}

/// Deterministic start offset, so monitors do not all fire at once and
/// keep the same phase across restarts.
fn start_offset(id: &str, interval: Duration) -> Duration {
    let mut h = DefaultHasher::new();
    id.hash(&mut h);
    let span = interval.min(Duration::from_secs(30)).as_millis().max(1) as u64;
    Duration::from_millis(h.finish() % span)
}

impl MonitorTask {
    async fn run(mut self) -> MonitorState {
        let interval = self.config.interval.0;
        self.publish_live(None, None);
        let mut next = Instant::now() + start_offset(&self.config.id, interval);
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                _ = tokio::time::sleep_until(next) => {
                    let now = Instant::now();
                    next += interval;
                    if next <= now {
                        next = now + interval;
                    }
                    self.tick().await;
                }
                cmd = self.rx.recv() => match cmd {
                    None => break,
                    Some(Command::RunNow) => {
                        if !self.check.is_passive() && !self.state.paused {
                            self.execute().await;
                        }
                    }
                    Some(Command::Push(report)) => self.push(report),
                    Some(Command::Pause(paused, ack)) => {
                        let fx = self.state.set_paused(paused, now_ms());
                        tracing::info!(monitor = %self.config.id, paused, "monitor pause changed");
                        self.apply_effects(&fx, None, now_ms());
                        self.publish_live(None, None);
                        let _ = ack.send(());
                    }
                }
            }
        }
        self.state
    }

    async fn tick(&mut self) {
        if self.state.paused {
            return;
        }
        if self.check.is_passive() {
            let silent = self.last_push.elapsed();
            if silent > self.config.interval.0 {
                let r = CheckResult::down(format!(
                    "no push received for {}",
                    Dur(Duration::from_secs(silent.as_secs()))
                ));
                self.process(r, now_ms());
            }
            return;
        }
        self.execute().await;
    }

    async fn execute(&mut self) {
        let Ok(_permit) = self.shared.semaphore.acquire().await else {
            return;
        };
        let ts = now_ms();
        let run = self.check.run(&self.shared.ctx, self.config.timeout.0);
        let result = tokio::select! {
            r = run => r,
            _ = self.cancel.cancelled() => return,
        };
        drop(_permit);
        self.process(result, ts);
    }

    fn push(&mut self, report: PushReport) {
        self.last_push = Instant::now();
        if self.state.paused {
            return;
        }
        let r = CheckResult {
            outcome: report.outcome,
            latency: report.latency,
            message: report.message,
            cert_expiry: None,
        };
        self.process(r, now_ms());
    }

    fn process(&mut self, mut result: CheckResult, ts: i64) {
        if result.outcome == Outcome::Up
            && let (Some(limit), Some(lat)) = (self.config.degraded_latency, result.latency)
            && lat > limit.0
        {
            result.outcome = Outcome::Degraded;
            result.message.push_str(&format!(" (latency above {limit})"));
        }
        let maintenance = self.shared.maintenance_for(&self.config, ts);
        let dependency = self.dependency_down();
        let ctx = Context {
            maintenance: maintenance.as_deref(),
            dependency_down: dependency.as_deref(),
        };
        let fx = self.state.apply(result.outcome, &ctx, ts, &self.policy);

        let hb_status = if maintenance.is_some() {
            Status::Maintenance
        } else {
            result.outcome.status()
        };
        let latency_us = result.latency.map(|l| i64::try_from(l.as_micros()).unwrap_or(i64::MAX));
        self.shared.writer.send(WriteOp::Heartbeat(Heartbeat {
            monitor_id: self.config.id.clone(),
            ts,
            status: hb_status,
            latency_us,
            message: result.message.clone(),
        }));
        self.shared.metrics.observe(
            &self.config.id,
            result.outcome,
            result.latency.map(|l| l.as_secs_f64()),
            result.cert_expiry,
        );
        tracing::debug!(monitor = %self.config.id, outcome = result.outcome.as_str(), message = %result.message, "check finished");
        self.apply_effects(&fx, Some(&result), ts);
        self.publish_live(Some(&result), Some(ts));
    }

    fn apply_effects(&mut self, fx: &Effects, result: Option<&CheckResult>, ts: i64) {
        let message = result.map(|r| r.message.clone()).unwrap_or_default();
        if let Some((from, to)) = fx.transition {
            tracing::info!(
                monitor = %self.config.id,
                from = from.as_str(),
                to = to.as_str(),
                suppressed = fx.suppressed.as_deref().unwrap_or(""),
                message = %message,
                "status changed"
            );
            self.shared.writer.send(WriteOp::Event(EventRecord {
                monitor_id: self.config.id.clone(),
                ts,
                from: Some(from),
                to,
                message: message.clone(),
                suppressed_reason: fx.suppressed.clone(),
            }));
        }
        self.shared.metrics.set_status(&self.config.id, self.state.status);
        if let Some(kind) = fx.notify {
            let n = Notification {
                event: kind,
                monitor_id: self.config.id.clone(),
                monitor_name: self.config.name.clone(),
                monitor_type: self.config.check.type_name().into(),
                target: self.config.check.target(),
                group: self.config.group.clone(),
                tags: self.config.effective_tags.clone(),
                status: self.state.status,
                previous_status: fx.transition.map(|(from, _)| from),
                message,
                timestamp: ts,
                since: self.state.since,
                latency_ms: result.and_then(|r| r.latency).map(|l| l.as_secs_f64() * 1000.0),
            };
            self.shared.dispatcher.send(n, self.config.notify.clone());
        }
        if fx.persist {
            self.shared
                .writer
                .send(WriteOp::State(self.config.id.clone(), self.state.persisted()));
        }
    }

    fn dependency_down(&self) -> Option<String> {
        if self.config.depends_on.is_empty() {
            return None;
        }
        let live = self.shared.live.read().ok()?;
        self.config
            .depends_on
            .iter()
            .find(|d| live.get(d.as_str()).is_some_and(|v| v.status == Status::Down))
            .cloned()
    }

    fn publish_live(&self, result: Option<&CheckResult>, ts: Option<i64>) {
        let Ok(mut live) = self.shared.live.write() else { return };
        let entry = live.entry(self.config.id.clone()).or_default();
        entry.status = self.state.status;
        entry.since = self.state.since;
        entry.paused = self.state.paused;
        entry.flapping = self.state.flapping;
        entry.consecutive_failures = self.state.fails;
        if let (Some(r), Some(ts)) = (result, ts) {
            entry.last_check = Some(ts);
            entry.outcome = Some(r.outcome.status());
            entry.latency_ms = r.latency.map(|l| l.as_secs_f64() * 1000.0);
            entry.message = Some(r.message.clone());
            if r.cert_expiry.is_some() {
                entry.cert_expiry = r.cert_expiry;
            }
        }
        entry.maintenance = (self.state.status == Status::Maintenance)
            .then(|| self.shared.maintenance_for(&self.config, now_ms()))
            .flatten();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_are_stable_and_bounded() {
        let a = start_offset("router", Duration::from_secs(60));
        assert_eq!(a, start_offset("router", Duration::from_secs(60)));
        assert!(a < Duration::from_secs(30));
        assert!(start_offset("x", Duration::from_secs(5)) < Duration::from_secs(5));
    }
}
