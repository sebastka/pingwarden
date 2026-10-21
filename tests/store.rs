//! Store behaviour on real PostgreSQL and MariaDB servers.

mod common;

use pingwarden::config::RetentionConfig;
use pingwarden::model::{Status, now_ms};
use pingwarden::store::{
    Acknowledgement, EventRecord, Heartbeat, MonitorMeta, NotificationFilter, NotificationRecord, PersistedState,
    RuntimeWindow, Silence, WindowSelection,
};

fn meta(id: &str) -> MonitorMeta {
    MonitorMeta {
        id: id.to_owned(),
        name: format!("Monitor {id}"),
        kind: "tcp".into(),
        target: "example.com:443".into(),
        description: None,
    }
}

fn hb(id: &str, ts: i64, status: Status, latency_us: Option<i64>) -> Heartbeat {
    Heartbeat {
        monitor_id: id.to_owned(),
        ts,
        status,
        latency_us,
        message: "ok ✓".into(),
    }
}

#[tokio::test]
async fn store_roundtrips() {
    for (name, url) in common::database_urls() {
        eprintln!("testing {name}");
        let store = common::store(&url).await;
        // Migrations are idempotent.
        store.migrate().await.unwrap();

        let a = common::unique("a");
        let b = common::unique("b");
        let now = now_ms();
        store.sync_monitors(&[meta(&a), meta(&b)], now).await.unwrap();
        // Upsert path.
        store.sync_monitors(&[meta(&a), meta(&b)], now + 1).await.unwrap();

        let state = PersistedState {
            status: Status::Down,
            since: now,
            notified_status: Some(Status::Down),
            last_notified_at: Some(now),
            paused: true,
            ack: Some(Acknowledgement {
                by: "oidc:alice".into(),
                at: now,
                comment: Some("on it ✓".into()),
            }),
            silence: Some(Silence {
                until: now + 3_600_000,
                by: "token:ops".into(),
            }),
        };
        store.save_state(&a, &state, now).await.unwrap();
        assert_eq!(store.load_states().await.unwrap().get(&a), Some(&state), "{name}");
        let mut updated = state.clone();
        updated.notified_status = None;
        updated.paused = false;
        updated.ack = None;
        updated.silence = None;
        store.save_state(&a, &updated, now + 5).await.unwrap();
        let states = store.load_states().await.unwrap();
        assert_eq!(states.get(&a), Some(&updated), "{name}");

        // Two batches in the same hour exercise the additive rollup upsert,
        // including NULL latencies.
        let hour = (now / 3_600_000) * 3_600_000;
        store
            .insert_heartbeats(&[
                hb(&a, hour + 1, Status::Up, Some(1000)),
                hb(&a, hour + 2, Status::Down, None),
                hb(&b, hour + 3, Status::Maintenance, Some(5)),
            ])
            .await
            .unwrap();
        store
            .insert_heartbeats(&[
                hb(&a, hour + 4, Status::Degraded, Some(250)),
                hb(&a, hour + 5, Status::Up, Some(4000)),
            ])
            .await
            .unwrap();
        let rows = store.heartbeats(&a, hour, hour + 3_600_000, 10).await.unwrap();
        assert_eq!(rows.len(), 4, "{name}");
        assert_eq!(rows[0].ts, hour + 5, "newest first");
        assert_eq!(rows[0].message.as_deref(), Some("ok ✓"));

        let hourly = store.rollups(&a, 3600, hour, hour + 1).await.unwrap();
        assert_eq!(hourly.len(), 1, "{name}");
        let r = &hourly[0];
        assert_eq!((r.up, r.degraded, r.down, r.maintenance), (2, 1, 1, 0), "{name}");
        assert_eq!((r.latency_count, r.latency_sum_us), (3, 5250), "{name}");
        assert_eq!((r.latency_min_us, r.latency_max_us), (Some(250), Some(4000)), "{name}");
        let daily = store.rollups(&a, 86_400, 0, now + 86_400_000).await.unwrap();
        assert_eq!(daily.iter().map(|r| r.up).sum::<i64>(), 2, "{name}");
        let maint = store.rollups(&b, 3600, hour, hour + 1).await.unwrap();
        assert_eq!((maint[0].maintenance, maint[0].latency_count), (1, 0), "{name}");
        // Every monitor in one query.
        let all = store.rollups_all(3600, hour, hour + 1).await.unwrap();
        assert_eq!(all[&a], hourly, "{name}");
        assert_eq!(all[&b], maint, "{name}");

        store
            .insert_event(&EventRecord {
                monitor_id: a.clone(),
                ts: now,
                from: Some(Status::Up),
                to: Status::Down,
                message: "x".repeat(5000),
                suppressed_reason: Some("flapping".into()),
            })
            .await
            .unwrap();
        let events = store.events(Some(&a), now - 1, now + 1, 10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].from, Some(Status::Up));
        assert!(events[0].message.as_ref().unwrap().len() <= 1024);

        // Inserts return the row as listed, with its id.
        let second = store
            .insert_event(&EventRecord {
                monitor_id: a.clone(),
                ts: now + 1,
                from: Some(Status::Down),
                to: Status::Up,
                message: "back".into(),
                suppressed_reason: None,
            })
            .await
            .unwrap();
        assert!(second.id > events[0].id, "{name}");
        assert_eq!(store.events(Some(&a), now, now + 2, 10).await.unwrap()[0].id, second.id);

        let failed = store
            .insert_notification(&NotificationRecord {
                ts: now,
                monitor_id: Some(a.clone()),
                notifier: "hook".into(),
                event: "down".into(),
                success: false,
                error: Some("HTTP 500".into()),
            })
            .await
            .unwrap();
        let sent = store
            .insert_notification(&NotificationRecord {
                ts: now,
                monitor_id: Some(a.clone()),
                notifier: "mail".into(),
                event: "up".into(),
                success: true,
                error: None,
            })
            .await
            .unwrap();
        assert!(sent.id > failed.id && failed.error.as_deref() == Some("HTTP 500"));
        let n = store
            .notifications(&NotificationFilter::default(), now - 1, now + 1, 100)
            .await
            .unwrap();
        assert!(
            n.iter()
                .any(|n| n.monitor_id.as_deref() == Some(a.as_str()) && !n.success)
        );
        let only = |f: NotificationFilter| {
            let store = store.clone();
            async move { store.notifications(&f, now - 1, now + 1, 100).await.unwrap() }
        };
        let mine = |extra: NotificationFilter| NotificationFilter {
            monitor: Some(a.clone()),
            ..extra
        };
        assert_eq!(only(mine(NotificationFilter::default())).await.len(), 2, "{name}");
        let failures = only(mine(NotificationFilter {
            success: Some(false),
            ..NotificationFilter::default()
        }))
        .await;
        assert_eq!(
            failures.iter().map(|n| n.id).collect::<Vec<_>>(),
            vec![failed.id],
            "{name}"
        );
        let mail = only(mine(NotificationFilter {
            notifier: Some("mail".into()),
            event: Some("up".into()),
            ..NotificationFilter::default()
        }))
        .await;
        assert_eq!(mail.iter().map(|n| n.id).collect::<Vec<_>>(), vec![sent.id], "{name}");
        assert!(
            only(mine(NotificationFilter {
                event: Some("reminder".into()),
                ..NotificationFilter::default()
            }))
            .await
            .is_empty()
        );

        // Runtime maintenance windows: stored, listed, ended, purged after a week.
        let w = RuntimeWindow {
            id: common::unique("window"),
            description: Some("router swap".into()),
            selection: WindowSelection {
                monitors: vec![a.clone()],
                tags: vec!["prod".into()],
                ..WindowSelection::default()
            },
            start_ms: now,
            end_ms: now + 3_600_000,
            created_by: "oidc:alice".into(),
            created_at: now,
        };
        store.insert_window(&w).await.unwrap();
        assert!(store.window_exists(&w.id).await.unwrap());
        let listed = store.load_windows(now).await.unwrap();
        assert!(listed.contains(&w), "{name}");
        store.end_window(&w.id, now + 10).await.unwrap();
        // Ending again later does not move the end.
        store.end_window(&w.id, now + 20).await.unwrap();
        let ended = store.load_windows(now).await.unwrap();
        let ended = ended.iter().find(|x| x.id == w.id).unwrap();
        assert_eq!(ended.end_ms, now + 10, "{name}");
        assert!(store.load_windows(now + 11).await.unwrap().iter().all(|x| x.id != w.id));

        // Removing `b` from the configuration flags it; cleanup purges it
        // once `removed_monitors` has elapsed.
        store.sync_monitors(&[meta(&a)], now).await.unwrap();
        let retention = RetentionConfig {
            heartbeats: pingwarden::config::Dur::ZERO,
            removed_monitors: pingwarden::config::Dur::millis(1),
            ..RetentionConfig::default()
        };
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let stats = store.cleanup(&retention, now_ms()).await.unwrap();
        assert!(stats.monitors >= 1, "{name}: {stats:?}");
        assert!(store.window_exists(&w.id).await.unwrap(), "{name}: kept for a week");
        store.cleanup(&retention, now + 8 * 86_400_000).await.unwrap();
        assert!(
            !store.window_exists(&w.id).await.unwrap(),
            "{name}: purged after a week"
        );
        assert!(store.rollups(&b, 3600, 0, i64::MAX).await.unwrap().is_empty());
        assert_eq!(store.heartbeats(&a, 0, i64::MAX, 100).await.unwrap().len(), 4);

        // Old heartbeats go once their retention elapsed.
        store
            .insert_heartbeats(&[hb(&a, 1000, Status::Up, None)])
            .await
            .unwrap();
        let retention = RetentionConfig {
            heartbeats: pingwarden::config::Dur::secs(86_400),
            ..RetentionConfig::default()
        };
        store.cleanup(&retention, now_ms()).await.unwrap();
        assert_eq!(store.heartbeats(&a, 0, 2000, 10).await.unwrap().len(), 0, "{name}");
    }
}

#[tokio::test]
async fn leader_lock_is_exclusive() {
    for (name, url) in common::database_urls() {
        let store = common::store(&url).await;
        let other = common::store(&url).await;
        let lock_name = common::unique("leader");
        let mut first = store.try_lock(&lock_name).await.unwrap().expect("first lock");
        assert!(
            other.try_lock(&lock_name).await.unwrap().is_none(),
            "{name}: lock must be exclusive"
        );
        first.check().await.unwrap();
        first.release().await;
        let second = other.try_lock(&lock_name).await.unwrap();
        assert!(second.is_some(), "{name}: lock must be free after release");
        // Dropping the lock closes its connection, which frees it too.
        drop(second);
        let mut freed = None;
        for _ in 0..50 {
            freed = store.try_lock(&lock_name).await.unwrap();
            if freed.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(freed.is_some(), "{name}: lock must be free after drop");
    }
}
