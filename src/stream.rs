//! Live change feed behind `GET /api/v1/stream` (server-sent events).
//!
//! The engine publishes changes on a broadcast channel; every stream holds a
//! receiver. A receiver that falls behind loses the oldest changes and is told
//! to resynchronise, so a slow client never holds memory or slows the engine.

use std::sync::Arc;

use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast};

use crate::store::{EventRow, NotificationRow};

/// Concurrent streams accepted; more are refused with 503.
pub const MAX_STREAMS: usize = 64;
/// Changes buffered per receiver before it lags.
const CAPACITY: usize = 256;

#[derive(Clone, Debug)]
pub enum Change {
    /// A status transition, as listed by `/events`.
    Transition(EventRow),
    /// A notification delivery, as listed by `/notifications`.
    Notification(NotificationRow),
    /// Live state changed without a transition (pause, acknowledgement, silence…).
    Monitor(String),
    /// A maintenance window was created, ended, started or stopped.
    Maintenance,
    /// The configuration was reloaded.
    Reload,
}

impl Change {
    /// The SSE `event:` name.
    pub fn name(&self) -> &'static str {
        match self {
            Change::Transition(_) => "transition",
            Change::Notification(_) => "notification",
            Change::Monitor(_) => "monitor",
            Change::Maintenance => "maintenance",
            Change::Reload => "reload",
        }
    }

    /// The SSE `data:` payload (JSON on one line).
    pub fn data(&self) -> String {
        match self {
            Change::Transition(e) => serde_json::to_string(e).unwrap_or_default(),
            Change::Notification(n) => serde_json::to_string(n).unwrap_or_default(),
            Change::Monitor(id) => json!({ "id": id }).to_string(),
            Change::Maintenance | Change::Reload => "{}".into(),
        }
    }
}

#[derive(Clone)]
pub struct Hub {
    tx: broadcast::Sender<Arc<Change>>,
    slots: Arc<Semaphore>,
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl Hub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CAPACITY);
        Self {
            tx,
            slots: Arc::new(Semaphore::new(MAX_STREAMS)),
        }
    }

    /// Publish a change; without subscribers it is simply dropped.
    pub fn publish(&self, change: Change) {
        let _ = self.tx.send(Arc::new(change));
    }

    /// A receiver and the slot it occupies, or `None` when all slots are taken.
    pub fn subscribe(&self) -> Option<(broadcast::Receiver<Arc<Change>>, OwnedSemaphorePermit)> {
        let permit = self.slots.clone().try_acquire_owned().ok()?;
        Some((self.tx.subscribe(), permit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn caps_streams_and_reports_lag() {
        let hub = Hub::new();
        let mut held = Vec::new();
        for _ in 0..MAX_STREAMS {
            held.push(hub.subscribe().expect("slot"));
        }
        assert!(hub.subscribe().is_none());
        held.pop();
        let (mut rx, _permit) = hub.subscribe().expect("slot freed");
        for _ in 0..CAPACITY + 5 {
            hub.publish(Change::Reload);
        }
        assert!(matches!(rx.recv().await, Err(broadcast::error::RecvError::Lagged(_))));
        assert_eq!(rx.recv().await.unwrap().name(), "reload");
        assert_eq!(Change::Monitor("web".into()).data(), r#"{"id":"web"}"#);
    }
}
