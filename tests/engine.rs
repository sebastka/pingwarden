//! End to end: real checks, the state machine, notifications through a
//! webhook, push monitors and configuration reloads, on a real database.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::routing::post;
use axum::{Json, Router};
use pingwarden::engine::{CommandError, Engine, PushReport, WindowError};
use pingwarden::maintenance::WindowRequest;
use pingwarden::metrics::Metrics;
use pingwarden::model::{Outcome, Status, now_ms};
use pingwarden::store::{Acknowledgement, Silence};
use pingwarden::stream::Change;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

async fn webhook_receiver() -> (String, mpsc::UnboundedReceiver<Value>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let app = Router::new().route(
        "/hook",
        post(move |Json(body): Json<Value>| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(body);
                "ok"
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/hook"), rx)
}

async fn wait_for(engine: &Engine, id: &str, status: Status) {
    for _ in 0..100 {
        if engine.live().get(id).is_some_and(|v| v.status == status) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{id} never became {status:?}: {:?}", engine.live().get(id));
}

async fn next_event(rx: &mut mpsc::UnboundedReceiver<Value>) -> Value {
    tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("no notification received")
        .expect("channel closed")
}

fn config(url: &str, hook: &str, target: &str, token: &str, with_tcp: bool) -> String {
    let tcp = if with_tcp {
        format!(
            r#"
  - id: svc
    type: tcp
    host: "{}"
    port: {}
    group: core
    interval: 1s
    timeout: 1s
    failure_threshold: 2"#,
            target.split(':').next().unwrap(),
            target.split(':').nth(1).unwrap()
        )
    } else {
        String::new()
    };
    format!(
        r#"
database:
  url: "{url}"
retention:
  cleanup_interval: 1h
notifiers:
  hook:
    type: webhook
    url: "{hook}"
defaults:
  notify: [hook]
groups:
  - id: core
    tags: [prod]
monitors:{tcp}
  - id: job
    type: push
    token: "{token}"
    interval: 1h
"#
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn monitors_notify_and_reload() {
    for (name, url) in common::database_urls() {
        eprintln!("testing {name}");
        let store = common::store(&url).await;
        let (hook, mut events) = webhook_receiver().await;

        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        let accept = tokio::spawn(async move {
            loop {
                let _ = target.accept().await;
            }
        });

        let token = common::unique("token").replace('-', "_");
        let cfg = pingwarden::config::from_str(&config(&url, &hook, &addr, &token, true)).unwrap();
        let svc_tags = cfg.monitors[0].effective_tags.clone();
        assert_eq!(svc_tags, vec!["prod"]);
        let engine = Engine::start(Arc::new(cfg), store.clone(), Metrics::new())
            .await
            .unwrap();

        wait_for(&engine, "svc", Status::Up).await;
        assert_eq!(engine.group_statuses(), vec![("core".to_owned(), Status::Up)]);

        // Close the port: two failures make the service down and notify.
        accept.abort();
        let _ = accept.await;
        let down = next_event(&mut events).await;
        assert_eq!(down["event"], "down", "{down}");
        assert_eq!(down["monitor_id"], "svc");
        assert_eq!(down["group"], "core");
        assert_eq!(down["tags"][0], "prod");
        assert_eq!(engine.group_statuses(), vec![("core".to_owned(), Status::Down)]);

        // Push monitors take results from the API.
        engine
            .push(
                &token,
                PushReport {
                    outcome: Outcome::Down,
                    message: "backup failed".into(),
                    latency: None,
                },
            )
            .await
            .unwrap();
        wait_for(&engine, "job", Status::Pending).await;
        assert!(
            engine
                .push(
                    "wrong-token-wrong-token",
                    PushReport {
                        outcome: Outcome::Up,
                        message: String::new(),
                        latency: None
                    }
                )
                .await
                .is_err()
        );

        // Pause and resume.
        engine.set_paused("svc", true).await.unwrap();
        wait_for(&engine, "svc", Status::Paused).await;
        engine.set_paused("svc", false).await.unwrap();

        // Reload without the TCP monitor.
        let cfg = pingwarden::config::from_str(&config(&url, &hook, &addr, &token, false)).unwrap();
        engine.apply(Arc::new(cfg)).await.unwrap();
        assert!(!engine.live().contains_key("svc"));
        assert!(engine.live().contains_key("job"));

        engine.shutdown().await;
        let beats = store.heartbeats("svc", 0, i64::MAX, 1000).await.unwrap();
        assert!(beats.iter().any(|b| b.status == Status::Up), "{name}");
        assert!(beats.iter().any(|b| b.status == Status::Down), "{name}");
        let events = store.events(Some("svc"), 0, i64::MAX, 100).await.unwrap();
        assert!(events.iter().any(|e| e.to == Status::Down), "{name}");
        let states = store.load_states().await.unwrap();
        assert_eq!(states["job"].status, Status::Pending, "{name}");
    }
}

/// Receive notifications for `wait`; returns their event kinds.
async fn drain(rx: &mut mpsc::UnboundedReceiver<Value>, wait: Duration) -> Vec<String> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Some(v)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        out.push(v["event"].as_str().unwrap_or_default().to_owned());
    }
    out
}

/// Wait for a live change matching `pred`.
async fn next_change(
    rx: &mut tokio::sync::broadcast::Receiver<Arc<Change>>,
    pred: impl Fn(&Change) -> bool,
) -> Arc<Change> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(c)) if pred(&c) => return c,
            Ok(_) => continue,
            Err(_) => panic!("no matching change"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acknowledgements_silences_and_runtime_windows() {
    for (name, url) in common::database_urls() {
        eprintln!("testing {name}");
        let store = common::store(&url).await;
        let (hook, mut notes) = webhook_receiver().await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            loop {
                let _ = target.accept().await;
            }
        });
        let svc = common::unique("svc");
        // Unique: the other test leaves a pending `job` in the shared database.
        let job = common::unique("job");
        let token = common::unique("token").replace('-', "_");
        let yaml = format!(
            r#"
database: {{ url: "{url}" }}
notifiers:
  hook: {{ type: webhook, url: "{hook}" }}
defaults: {{ notify: [hook], slo: 99.9 }}
monitors:
  - {{ id: {svc}, type: tcp, host: "127.0.0.1", port: {port}, interval: 1s, timeout: 1s, failure_threshold: 1, renotify_every: 1s }}
  - {{ id: {job}, type: push, token: "{token}", interval: 1h }}
"#,
            port = addr.port()
        );
        let cfg = pingwarden::config::from_str(&yaml).unwrap();
        assert_eq!(cfg.monitors[0].slo, Some(99.9));
        let engine = Engine::start(Arc::new(cfg), store.clone(), Metrics::new())
            .await
            .unwrap();
        let (mut changes, _slot, _cancel) = engine.subscribe().expect("stream slot");
        wait_for(&engine, &svc, Status::Up).await;

        // Down: notified, then acknowledged, which stops the reminders.
        accept.abort();
        let _ = accept.await;
        assert_eq!(next_event(&mut notes).await["event"], "down");
        let ack = Acknowledgement {
            by: "token:test".into(),
            at: now_ms(),
            comment: Some("looking".into()),
        };
        engine.acknowledge(&svc, Some(ack.clone())).await.unwrap();
        let c = next_change(&mut changes, |c| matches!(c, Change::Monitor(id) if *id == svc)).await;
        assert_eq!(c.data(), format!(r#"{{"id":"{svc}"}}"#));
        assert_eq!(engine.live()[&svc].acknowledged, Some(ack));
        drain(&mut notes, Duration::from_millis(500)).await;
        let quiet = drain(&mut notes, Duration::from_secs(3)).await;
        assert!(!quiet.contains(&"reminder".to_owned()), "{name}: {quiet:?}");
        // Only a problem can be acknowledged.
        assert!(matches!(
            engine.acknowledge(&job, Some(ack_by("x"))).await,
            Err(CommandError::NotAcknowledgeable(Status::Unknown))
        ));
        // Withdrawn: reminders resume.
        engine.acknowledge(&svc, None).await.unwrap();
        let resumed = drain(&mut notes, Duration::from_secs(4)).await;
        assert!(resumed.contains(&"reminder".to_owned()), "{name}: {resumed:?}");

        // Silenced: the recovery is recorded as suppressed, and not sent.
        let until = now_ms() + 3_600_000;
        engine
            .silence(
                &svc,
                Some(Silence {
                    until,
                    by: "token:test".into(),
                }),
            )
            .await
            .unwrap();
        assert_eq!(engine.live()[&svc].silenced_until, Some(until));
        drain(&mut notes, Duration::from_millis(300)).await;
        let target = TcpListener::bind(addr).await.unwrap();
        let accept = tokio::spawn(async move {
            loop {
                let _ = target.accept().await;
            }
        });
        let up = next_change(
            &mut changes,
            |c| matches!(c, Change::Transition(e) if e.to == Status::Up),
        )
        .await;
        let Change::Transition(e) = &*up else { unreachable!() };
        assert!(e.id > 0);
        assert!(
            e.suppressed_reason
                .as_deref()
                .is_some_and(|r| r.starts_with("silenced by token:test until ")),
            "{name}: {e:?}"
        );
        assert!(drain(&mut notes, Duration::from_secs(2)).await.is_empty(), "{name}");

        // A runtime maintenance window turns the monitor to maintenance; ending it brings it back.
        let w = engine
            .create_window(
                WindowRequest {
                    id: Some(common::unique("w")),
                    monitors: vec![svc.clone()],
                    duration: Some("1h".into()),
                    ..WindowRequest::default()
                },
                "token:test",
            )
            .await
            .unwrap();
        next_change(&mut changes, |c| matches!(c, Change::Maintenance)).await;
        wait_for(&engine, &svc, Status::Maintenance).await;
        assert_eq!(engine.live()[&svc].maintenance.as_deref(), Some(w.id.as_str()));
        let again = WindowRequest {
            id: Some(w.id.clone()),
            all: true,
            duration: Some("1h".into()),
            ..WindowRequest::default()
        };
        assert!(matches!(
            engine.create_window(again, "token:test").await,
            Err(WindowError::Conflict(_))
        ));
        let ended = engine.end_window(&w.id).await.unwrap();
        assert!(ended.end_ms <= now_ms());
        wait_for(&engine, &svc, Status::Up).await;
        assert!(matches!(engine.end_window("nope").await, Err(WindowError::Unknown)));
        assert_eq!(
            store
                .load_windows(0)
                .await
                .unwrap()
                .iter()
                .filter(|x| x.id == w.id)
                .count(),
            1
        );

        engine.shutdown().await;
        accept.abort();
        let states = store.load_states().await.unwrap();
        assert_eq!(states[&svc].silence.as_ref().map(|s| s.until), Some(until), "{name}");
        assert_eq!(states[&svc].ack, None, "{name}");
    }
}

fn ack_by(by: &str) -> Acknowledgement {
    Acknowledgement {
        by: by.into(),
        at: now_ms(),
        comment: None,
    }
}
