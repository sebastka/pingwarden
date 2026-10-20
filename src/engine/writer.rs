//! Batched, ordered database writes. Monitors never wait for the database:
//! they enqueue operations which a single task flushes every second (or as
//! soon as a batch is full). While the database is unreachable, operations
//! are kept and retried, up to a bound beyond which heartbeats are dropped.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::metrics::Metrics;
use crate::model::now_ms;
use crate::store::{EventRecord, Heartbeat, NotificationRecord, PersistedState, Store};

const QUEUE: usize = 4096;
const BATCH: usize = 500;
const MAX_PENDING_HEARTBEATS: usize = 50_000;
const MAX_PENDING_OTHER: usize = 10_000;

#[derive(Debug)]
pub enum WriteOp {
    Heartbeat(Heartbeat),
    Event(EventRecord),
    State(String, PersistedState),
    Notification(NotificationRecord),
    /// Flush everything, then acknowledge.
    Flush(tokio::sync::oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct Writer {
    tx: mpsc::Sender<WriteOp>,
    metrics: Metrics,
}

impl Writer {
    pub fn send(&self, op: WriteOp) {
        if let Err(mpsc::error::TrySendError::Full(op) | mpsc::error::TrySendError::Closed(op)) = self.tx.try_send(op) {
            self.metrics.heartbeat_dropped();
            tracing::warn!(?op, "database write queue is full; dropping");
        }
    }

    /// Wait until everything enqueued so far has been written (or given up).
    pub async fn flush(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(WriteOp::Flush(tx)).await.is_ok() {
            let _ = tokio::time::timeout(Duration::from_secs(15), rx).await;
        }
    }

    /// Start the writer task. It stops after `shutdown` once its queue is drained.
    pub fn spawn(store: Store, metrics: Metrics, shutdown: CancellationToken) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(QUEUE);
        let task = tokio::spawn(run(store, metrics.clone(), rx, shutdown));
        (Self { tx, metrics }, task)
    }
}

#[derive(Default)]
struct Pending {
    heartbeats: VecDeque<Heartbeat>,
    events: VecDeque<EventRecord>,
    states: HashMap<String, PersistedState>,
    notifications: VecDeque<NotificationRecord>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.heartbeats.is_empty() && self.events.is_empty() && self.states.is_empty() && self.notifications.is_empty()
    }

    fn push(&mut self, op: WriteOp, metrics: &Metrics) -> Option<tokio::sync::oneshot::Sender<()>> {
        match op {
            WriteOp::Heartbeat(h) => {
                if self.heartbeats.len() >= MAX_PENDING_HEARTBEATS {
                    self.heartbeats.pop_front();
                    metrics.heartbeat_dropped();
                }
                self.heartbeats.push_back(h);
            }
            WriteOp::Event(e) => {
                if self.events.len() >= MAX_PENDING_OTHER {
                    self.events.pop_front();
                }
                self.events.push_back(e);
            }
            WriteOp::State(id, s) => {
                self.states.insert(id, s);
            }
            WriteOp::Notification(n) => {
                if self.notifications.len() >= MAX_PENDING_OTHER {
                    self.notifications.pop_front();
                }
                self.notifications.push_back(n);
            }
            WriteOp::Flush(ack) => return Some(ack),
        }
        None
    }

    async fn flush(&mut self, store: &Store) -> anyhow::Result<()> {
        // States first: they are small and the most valuable after a crash.
        let ids: Vec<String> = self.states.keys().cloned().collect();
        for id in ids {
            if let Some(s) = self.states.get(&id) {
                store.save_state(&id, s, now_ms()).await?;
            }
            self.states.remove(&id);
        }
        while let Some(e) = self.events.front() {
            store.insert_event(e).await?;
            self.events.pop_front();
        }
        while !self.heartbeats.is_empty() {
            let n = self.heartbeats.len().min(BATCH);
            let batch: Vec<Heartbeat> = self.heartbeats.iter().take(n).cloned().collect();
            store.insert_heartbeats(&batch).await?;
            self.heartbeats.drain(..n);
        }
        while let Some(n) = self.notifications.front() {
            store.insert_notification(n).await?;
            self.notifications.pop_front();
        }
        Ok(())
    }
}

async fn run(store: Store, metrics: Metrics, mut rx: mpsc::Receiver<WriteOp>, shutdown: CancellationToken) {
    let mut pending = Pending::default();
    let mut acks = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut backoff = Duration::ZERO;
    let mut retry_at = tokio::time::Instant::now();
    let mut closing = false;
    loop {
        tokio::select! {
            op = rx.recv() => match op {
                Some(op) => {
                    if let Some(ack) = pending.push(op, &metrics) {
                        acks.push(ack);
                    }
                    if pending.heartbeats.len() < BATCH && acks.is_empty() {
                        continue;
                    }
                }
                None => closing = true,
            },
            _ = tick.tick() => {}
            _ = shutdown.cancelled(), if !closing => {
                // Drain what is already queued, then stop.
                rx.close();
                continue;
            }
        }
        let now = tokio::time::Instant::now();
        if !pending.is_empty() && (now >= retry_at || closing || !acks.is_empty()) {
            match pending.flush(&store).await {
                Ok(()) => backoff = Duration::ZERO,
                Err(e) => {
                    metrics.db_error();
                    backoff = (backoff * 2).clamp(Duration::from_secs(1), Duration::from_secs(60));
                    retry_at = now + backoff;
                    tracing::error!(error = %format!("{e:#}"), retry_in = ?backoff, "database write failed");
                    if closing {
                        tracing::error!(
                            heartbeats = pending.heartbeats.len(),
                            "giving up on pending writes at shutdown"
                        );
                        pending = Pending::default();
                    }
                }
            }
        }
        if pending.is_empty() || closing {
            for ack in acks.drain(..) {
                let _ = ack.send(());
            }
        }
        if closing {
            return;
        }
    }
}
