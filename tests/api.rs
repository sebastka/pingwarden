//! The HTTP API of a leader: who-am-I, bulk rollups, the live stream,
//! acknowledgements, silences, runtime maintenance and effective configuration.

mod common;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use pingwarden::api::{self, AppState};
use pingwarden::config::Endpoints;
use pingwarden::engine::Engine;
use pingwarden::metrics::Metrics;
use serde_json::{Value, json};
use tokio::net::TcpListener;

const READ: &str = "api-test-read-token-0123456789";
const ADMIN: &str = "api-test-admin-token-0123456789";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leader_api() {
    let Some((_, url)) = common::database_urls().into_iter().next() else {
        return;
    };
    let site = common::unique("site");
    let push_token = common::unique("push").replace('-', "_");
    let yaml = format!(
        r#"
database: {{ url: "{url}" }}
server:
  api_tokens:
    - {{ name: reader, token: {READ}, scope: read }}
    - {{ name: ops, token: {ADMIN}, scope: admin }}
defaults: {{ slo: 99.5 }}
groups: [{{ id: web, tags: [public] }}]
monitors:
  - {{ id: {site}, type: push, token: "{push_token}", interval: 1h, group: web, failure_threshold: 1 }}
maintenance:
  - {{ id: configured, all: true, recurring: {{ days: [], start: "00:00", duration: 1s }} }}
"#
    );
    let config = Arc::new(pingwarden::config::from_str(&yaml).unwrap());
    let store = common::store(&url).await;
    let engine = Engine::start(config.clone(), store.clone(), Metrics::new())
        .await
        .unwrap();
    let (reload, _rx) = tokio::sync::mpsc::channel(1);
    let state = Arc::new(AppState {
        config: RwLock::new(config),
        engine: RwLock::new(Some(engine.clone())),
        store,
        metrics: Metrics::new(),
        reload,
        oidc: None,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/api/v1", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, api::router(state, &Endpoints::ALL))
            .await
            .unwrap()
    });
    let http = reqwest::Client::new();
    let get = |path: &str, token: &str| {
        let r = http.get(format!("{base}{path}")).bearer_auth(token);
        async move {
            let r = r.send().await.unwrap();
            (r.status().as_u16(), r.json::<Value>().await.unwrap_or(Value::Null))
        }
    };
    let post = |path: &str, body: Option<Value>| {
        let mut r = http.post(format!("{base}{path}")).bearer_auth(ADMIN);
        if let Some(b) = body {
            r = r.json(&b);
        }
        async move {
            let r = r.send().await.unwrap();
            (r.status().as_u16(), r.json::<Value>().await.unwrap_or(Value::Null))
        }
    };

    // Who am I.
    assert_eq!(
        get("/me", READ).await,
        (200, json!({"name": "reader", "kind": "token", "scope": "read"}))
    );
    assert_eq!(get("/me", ADMIN).await.1["scope"], "admin");

    // Monitor body additions and effective configuration.
    let (_, m) = get(&format!("/monitors/{site}"), READ).await;
    assert_eq!(m["slo"], 99.5);
    assert_eq!(m["acknowledged"], Value::Null);
    assert_eq!(m["silenced_until"], Value::Null);
    assert_eq!(m["cert_expires_at"], Value::Null);
    let (code, c) = get(&format!("/monitors/{site}/config"), READ).await;
    assert_eq!(code, 200);
    assert_eq!(c["monitor"], json!(site));
    assert_eq!(c["settings"]["slo"], 99.5);
    assert_eq!(c["settings"]["interval_seconds"], 3600.0);
    assert_eq!(c["check"], json!({"type": "push"}));
    assert!(!c.to_string().contains(&push_token));
    assert_eq!(get("/monitors/nope/config", READ).await.0, 404);

    // Bulk rollups: every monitor, even without data; bounded ranges.
    let (code, r) = get("/rollups?resolution=day&tag=public", READ).await;
    assert_eq!(code, 200);
    assert_eq!(r["resolution"], 86_400);
    assert_eq!(r["monitors"][&site], json!([]));
    assert_eq!(get("/rollups?tag=none", READ).await.1["monitors"], json!({}));
    assert_eq!(get("/rollups?resolution=hour&from=0&to=86400000000", READ).await.0, 400);
    assert_eq!(get("/rollups?resolution=week", READ).await.0, 400);

    // Delivery log filters are validated.
    assert_eq!(get("/notifications?success=maybe", READ).await.0, 400);
    assert_eq!(get("/notifications?event=nope", READ).await.0, 400);
    assert_eq!(
        get(&format!("/notifications?monitor={site}&success=false&event=down"), READ)
            .await
            .0,
        200
    );

    // The live stream, as text/event-stream.
    let mut stream = http
        .get(format!("{base}/stream"))
        .bearer_auth(READ)
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);
    assert!(
        stream.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let mut seen = String::new();
    let mut wait_for = async |needle: &str| {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !seen.contains(needle) {
            match tokio::time::timeout_at(deadline, stream.chunk()).await {
                Ok(Ok(Some(chunk))) => seen.push_str(&String::from_utf8_lossy(&chunk)),
                other => panic!("stream ended or timed out waiting for {needle:?}: {other:?}\n{seen}"),
            }
        }
    };

    // Acknowledge: only a problem; then a `monitor` change on the stream.
    let (code, err) = post(&format!("/monitors/{site}/ack"), None).await;
    assert_eq!(code, 409, "{err}");
    let pushed = http
        .get(format!("{}/push/{push_token}?status=down&msg=failed", base))
        .send()
        .await
        .unwrap();
    assert_eq!(pushed.status(), 200);
    wait_for("event: transition").await;
    assert_eq!(
        post(&format!("/monitors/{site}/ack"), Some(json!({"comment": "on it"})))
            .await
            .0,
        200
    );
    wait_for(&format!("event: monitor\ndata: {{\"id\":\"{site}\"}}")).await;
    let (_, m) = get(&format!("/monitors/{site}"), READ).await;
    assert_eq!(m["acknowledged"]["by"], "token:ops");
    assert_eq!(m["acknowledged"]["comment"], "on it");
    assert_eq!(post(&format!("/monitors/{site}/unack"), None).await.0, 200);
    assert_eq!(
        get(&format!("/monitors/{site}"), READ).await.1["acknowledged"],
        Value::Null
    );
    assert_eq!(post("/monitors/nope/ack", None).await.0, 404);

    // Silence: bounded, reported, lifted.
    assert_eq!(
        post(&format!("/monitors/{site}/silence"), Some(json!({"duration": "8d"})))
            .await
            .0,
        400
    );
    assert_eq!(post(&format!("/monitors/{site}/silence"), None).await.0, 400);
    let (code, s) = post(&format!("/monitors/{site}/silence"), Some(json!({"duration": "2h"}))).await;
    assert_eq!(code, 200, "{s}");
    let (_, m) = get(&format!("/monitors/{site}"), READ).await;
    assert_eq!(m["silenced_until"], s["silenced_until"]);
    assert_eq!(m["silenced_by"], "token:ops");
    assert_eq!(post(&format!("/monitors/{site}/unsilence"), None).await.0, 200);
    assert_eq!(
        get(&format!("/monitors/{site}"), READ).await.1["silenced_until"],
        Value::Null
    );

    // Runtime maintenance: created (201), listed, ended; configured windows stay.
    let id = common::unique("w");
    let (code, w) = post(
        "/maintenance",
        Some(json!({"id": id, "description": "swap", "groups": ["web"], "duration": "1h"})),
    )
    .await;
    assert_eq!(code, 201, "{w}");
    assert_eq!(w["source"], "api");
    assert_eq!(w["created_by"], "token:ops");
    assert_eq!(w["active"], true);
    assert_eq!(w["recurring"], false);
    assert_eq!(w["monitors"], json!([site]));
    assert_eq!(w["end"].as_i64().unwrap() - w["start"].as_i64().unwrap(), 3_600_000);
    wait_for("event: maintenance\ndata: {}").await;
    assert_eq!(
        post("/maintenance", Some(json!({"id": id, "all": true, "duration": "1h"})))
            .await
            .0,
        409
    );
    assert_eq!(post("/maintenance", Some(json!({"all": true}))).await.0, 400);
    assert_eq!(
        post("/maintenance", Some(json!({"monitors": ["nope"], "duration": "1h"})))
            .await
            .0,
        400
    );
    let (_, list) = get("/maintenance", READ).await;
    let configured = list
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["id"] == "configured")
        .unwrap();
    assert_eq!(
        (configured["source"].clone(), configured["recurring"].clone()),
        (json!("config"), json!(true))
    );
    assert_eq!(configured["start"], Value::Null);
    assert!(list.as_array().unwrap().iter().any(|x| x["id"] == json!(id)));
    assert_eq!(post("/maintenance/configured/end", None).await.0, 409);
    assert_eq!(post("/maintenance/nope/end", None).await.0, 404);
    let (code, ended) = post(&format!("/maintenance/{id}/end"), None).await;
    assert_eq!(code, 200);
    assert_eq!(ended["active"], false);
    assert_eq!(
        http.post(format!("{base}/maintenance"))
            .bearer_auth(READ)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    drop(stream);
    engine.shutdown().await;
}
