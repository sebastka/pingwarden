//! HTTP API: health, metrics, read-only monitor data for UIs, a few admin
//! actions and the push endpoint. See `docs/api.md`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};

use crate::config::{Config, Endpoints, MonitorConfig, TokenScope};
use crate::engine::{CommandError, Engine, LiveView, PushReport};
use crate::metrics::Metrics;
use crate::model::{Outcome, Status, now_ms};
use crate::store::{Rollup, Store};

pub type ReloadRequest = oneshot::Sender<Result<(), String>>;

pub struct AppState {
    pub config: RwLock<Arc<Config>>,
    pub engine: RwLock<Option<Arc<Engine>>>,
    pub store: Store,
    pub metrics: Metrics,
    pub reload: mpsc::Sender<ReloadRequest>,
}

impl AppState {
    fn config(&self) -> Arc<Config> {
        self.config.read().map(|c| c.clone()).expect("config lock poisoned")
    }

    fn engine(&self) -> Result<Arc<Engine>, ApiError> {
        self.engine.read().ok().and_then(|e| e.clone()).ok_or_else(|| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "this instance is on standby; another instance holds the leader lock".into(),
            )
        })
    }
}

type AppStateRef = Arc<AppState>;

/// Router for one listener, serving only the selected endpoint groups.
pub fn router(state: AppStateRef, serve: &[Endpoints]) -> Router {
    let mut root = Router::new();
    if serve.contains(&Endpoints::Health) {
        root = root
            .route("/healthz", get(|| async { "ok" }))
            .route("/readyz", get(readyz));
    }
    if serve.contains(&Endpoints::Metrics) {
        root = root.route("/metrics", get(metrics));
    }
    let mut v1 = Router::new();
    if serve.contains(&Endpoints::Api) {
        v1 = v1.merge(api_routes(state.clone()));
    }
    if serve.contains(&Endpoints::Push) {
        v1 = v1.route("/push/{token}", get(push).post(push));
    }
    root.nest("/api/v1", v1).with_state(state)
}

fn api_routes(state: AppStateRef) -> Router<AppStateRef> {
    Router::new()
        .route("/status", get(status))
        .route("/monitors", get(list_monitors))
        .route("/monitors/{id}", get(get_monitor))
        .route("/monitors/{id}/heartbeats", get(heartbeats))
        .route("/monitors/{id}/events", get(monitor_events))
        .route("/monitors/{id}/uptime", get(uptime))
        .route("/monitors/{id}/rollups", get(rollups))
        .route("/monitors/{id}/check", post(run_now))
        .route("/monitors/{id}/pause", post(pause))
        .route("/monitors/{id}/resume", post(resume))
        .route("/groups", get(groups))
        .route("/tags", get(tags))
        .route("/events", get(events))
        .route("/maintenance", get(maintenance))
        .route("/notifiers", get(notifiers))
        .route("/notifiers/{id}/test", post(test_notifier))
        .route("/notifications", get(notifications))
        .route("/reload", post(reload))
        .layer(middleware::from_fn_with_state(state, api_auth))
}

// ------------------------------------------------------------------ errors

#[derive(Debug)]
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %format!("{e:#}"), "API request failed");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

impl From<CommandError> for ApiError {
    fn from(e: CommandError) -> Self {
        let code = match e {
            CommandError::UnknownMonitor => StatusCode::NOT_FOUND,
            CommandError::Disabled => StatusCode::CONFLICT,
            CommandError::Busy => StatusCode::TOO_MANY_REQUESTS,
        };
        ApiError(code, e.to_string())
    }
}

fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("unknown {what}"))
}

type ApiResult<T> = Result<Json<T>, ApiError>;

// -------------------------------------------------------------------- auth

fn digest(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

/// Compare digests so that timing reveals neither content nor length.
fn token_eq(a: &str, b: &str) -> bool {
    let (a, b) = (digest(a), digest(b));
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

fn scope_of(config: &Config, headers: &HeaderMap) -> Option<TokenScope> {
    let presented = bearer(headers)?;
    // Check every token, so the time taken does not depend on which matched.
    config
        .server
        .api_tokens
        .iter()
        .filter(|t| token_eq(&t.token, presented))
        .map(|t| t.scope)
        .max()
}

async fn api_auth(State(state): State<AppStateRef>, req: Request, next: Next) -> Response {
    let config = state.config();
    let needed = if req.method() == Method::GET || req.method() == Method::HEAD {
        TokenScope::Read
    } else {
        TokenScope::Admin
    };
    let granted = scope_of(&config, req.headers()).or((config.server.anonymous_read).then_some(TokenScope::Read));
    match granted {
        Some(s) if s >= needed => next.run(req).await,
        Some(_) => ApiError(StatusCode::FORBIDDEN, "admin token required".into()).into_response(),
        None => {
            let mut r = ApiError(StatusCode::UNAUTHORIZED, "missing or invalid bearer token".into()).into_response();
            r.headers_mut()
                .insert(header::WWW_AUTHENTICATE, header::HeaderValue::from_static("Bearer"));
            r
        }
    }
}

// ------------------------------------------------------------ health/metrics

async fn readyz(State(state): State<AppStateRef>, Query(q): Query<HashMap<String, String>>) -> Response {
    let leader = state.engine.read().map(|e| e.is_some()).unwrap_or(false);
    let db = tokio::time::timeout(Duration::from_secs(3), state.store.ping()).await;
    let db_ok = matches!(db, Ok(Ok(())));
    let need_leader = q.get("role").is_some_and(|r| r == "leader");
    let ready = db_ok && (leader || !need_leader);
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(json!({ "ready": ready, "database": db_ok, "leader": leader })),
    )
        .into_response()
}

async fn metrics(State(state): State<AppStateRef>, headers: HeaderMap) -> Response {
    if let Some(expected) = &state.config().server.metrics_token
        && !bearer(&headers).is_some_and(|t| token_eq(t, expected))
    {
        return ApiError(StatusCode::UNAUTHORIZED, "missing or invalid bearer token".into()).into_response();
    }
    (
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        state.metrics.encode(),
    )
        .into_response()
}

// ------------------------------------------------------------------ monitors

#[derive(Serialize)]
struct MonitorBody {
    id: String,
    name: String,
    description: Option<String>,
    #[serde(rename = "type")]
    kind: &'static str,
    target: String,
    group: Option<String>,
    /// Own and inherited tags.
    tags: Vec<String>,
    enabled: bool,
    interval_seconds: f64,
    depends_on: Vec<String>,
    notify: Vec<String>,
    #[serde(flatten)]
    live: Option<LiveView>,
}

fn monitor_body(m: &MonitorConfig, live: Option<&LiveView>) -> MonitorBody {
    MonitorBody {
        id: m.id.clone(),
        name: m.name.clone(),
        description: m.description.clone(),
        kind: m.check.type_name(),
        target: m.check.target(),
        group: m.group.clone(),
        tags: m.effective_tags.clone(),
        enabled: m.enabled,
        interval_seconds: m.interval.0.as_secs_f64(),
        depends_on: m.depends_on.clone(),
        notify: m.notify.clone(),
        live: live.cloned(),
    }
}

#[derive(Deserialize)]
struct MonitorFilter {
    tag: Option<String>,
    group: Option<String>,
    status: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

async fn list_monitors(
    State(state): State<AppStateRef>,
    Query(f): Query<MonitorFilter>,
) -> ApiResult<Vec<MonitorBody>> {
    let engine = state.engine()?;
    let config = engine.config();
    let live = engine.live();
    let status = match f.status.as_deref() {
        Some(s) => {
            Some(Status::parse(s).ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, format!("unknown status {s:?}")))?)
        }
        None => None,
    };
    let out = config
        .monitors
        .iter()
        .filter(|m| f.tag.as_deref().is_none_or(|t| m.has_tag(t)))
        .filter(|m| f.group.as_deref().is_none_or(|g| m.group_path.iter().any(|p| p == g)))
        .filter(|m| f.kind.as_deref().is_none_or(|k| m.check.type_name() == k))
        .filter(|m| status.is_none_or(|s| live.get(&m.id).is_some_and(|v| v.status == s)))
        .map(|m| monitor_body(m, live.get(&m.id)))
        .collect();
    Ok(Json(out))
}

fn find_monitor(config: &Config, id: &str) -> Result<MonitorConfig, ApiError> {
    config
        .monitors
        .iter()
        .find(|m| m.id == id)
        .cloned()
        .ok_or_else(|| not_found("monitor"))
}

async fn get_monitor(State(state): State<AppStateRef>, Path(id): Path<String>) -> ApiResult<MonitorBody> {
    let engine = state.engine()?;
    let m = find_monitor(&engine.config(), &id)?;
    Ok(Json(monitor_body(&m, engine.live().get(&id))))
}

#[derive(Deserialize)]
struct Range {
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<i64>,
}

impl Range {
    fn resolve(&self, default_span_ms: i64) -> (i64, i64, i64) {
        let to = self.to.unwrap_or_else(|| now_ms() + 1);
        let from = self.from.unwrap_or(to - default_span_ms);
        (from, to, self.limit.unwrap_or(500).clamp(1, 10_000))
    }
}

const DAY_MS: i64 = 86_400_000;

/// Monitor history stays readable after removal from the configuration, so
/// only an id that was never stored is unknown; the database answers that.
async fn heartbeats(
    State(state): State<AppStateRef>,
    Path(id): Path<String>,
    Query(r): Query<Range>,
) -> ApiResult<Value> {
    let (from, to, limit) = r.resolve(DAY_MS);
    let rows = state.store.heartbeats(&id, from, to, limit).await?;
    Ok(Json(
        json!({ "monitor": id, "from": from, "to": to, "heartbeats": rows }),
    ))
}

async fn monitor_events(
    State(state): State<AppStateRef>,
    Path(id): Path<String>,
    Query(r): Query<Range>,
) -> ApiResult<Value> {
    let (from, to, limit) = r.resolve(30 * DAY_MS);
    let rows = state.store.events(Some(&id), from, to, limit).await?;
    Ok(Json(json!({ "monitor": id, "from": from, "to": to, "events": rows })))
}

async fn events(State(state): State<AppStateRef>, Query(r): Query<Range>) -> ApiResult<Value> {
    let (from, to, limit) = r.resolve(DAY_MS);
    let rows = state.store.events(None, from, to, limit).await?;
    Ok(Json(json!({ "from": from, "to": to, "events": rows })))
}

async fn notifications(State(state): State<AppStateRef>, Query(r): Query<Range>) -> ApiResult<Value> {
    let (from, to, limit) = r.resolve(7 * DAY_MS);
    let rows = state.store.notifications(from, to, limit).await?;
    Ok(Json(json!({ "from": from, "to": to, "notifications": rows })))
}

#[derive(Serialize)]
struct UptimeWindow {
    window: &'static str,
    /// Percentage of up or degraded results; null without data.
    uptime: Option<f64>,
    avg_latency_ms: Option<f64>,
    checks: i64,
    down: i64,
    maintenance: i64,
}

fn summarize(window: &'static str, rows: &[Rollup]) -> UptimeWindow {
    let mut total = Rollup::default();
    for r in rows {
        total.merge(r);
    }
    let available = total.up + total.degraded;
    let counted = available + total.down;
    UptimeWindow {
        window,
        uptime: (counted > 0).then(|| 100.0 * available as f64 / counted as f64),
        avg_latency_ms: (total.latency_count > 0)
            .then(|| total.latency_sum_us as f64 / total.latency_count as f64 / 1000.0),
        checks: counted + total.maintenance,
        down: total.down,
        maintenance: total.maintenance,
    }
}

async fn uptime(State(state): State<AppStateRef>, Path(id): Path<String>) -> ApiResult<Value> {
    let now = now_ms();
    let hourly = state.store.rollups(&id, 3600, now - 30 * DAY_MS, now + 1).await?;
    let daily = state.store.rollups(&id, 86_400, now - 365 * DAY_MS, now + 1).await?;
    // Buckets are aligned, so a window includes the partial oldest bucket.
    let since = |rows: &[Rollup], size: i64, span: i64| -> Vec<Rollup> {
        let cutoff = (now - span).div_euclid(size) * size;
        rows.iter().filter(|r| r.bucket >= cutoff).cloned().collect()
    };
    const HOUR_MS: i64 = 3_600_000;
    let windows = vec![
        summarize("24h", &since(&hourly, HOUR_MS, DAY_MS)),
        summarize("7d", &since(&hourly, HOUR_MS, 7 * DAY_MS)),
        summarize("30d", &since(&hourly, HOUR_MS, 30 * DAY_MS)),
        summarize("365d", &since(&daily, DAY_MS, 365 * DAY_MS)),
    ];
    Ok(Json(json!({ "monitor": id, "windows": windows })))
}

#[derive(Deserialize)]
struct RollupQuery {
    resolution: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
}

async fn rollups(
    State(state): State<AppStateRef>,
    Path(id): Path<String>,
    Query(q): Query<RollupQuery>,
) -> ApiResult<Value> {
    let (res, span) = match q.resolution.as_deref().unwrap_or("hour") {
        "hour" => (3600, 7 * DAY_MS),
        "day" => (86_400, 365 * DAY_MS),
        other => {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!("unknown resolution {other:?} (hour or day)"),
            ));
        }
    };
    let to = q.to.unwrap_or_else(|| now_ms() + 1);
    let from = q.from.unwrap_or(to - span);
    let rows = state.store.rollups(&id, res, from, to).await?;
    Ok(Json(json!({ "monitor": id, "resolution": res, "rollups": rows })))
}

async fn run_now(State(state): State<AppStateRef>, Path(id): Path<String>) -> ApiResult<Value> {
    state.engine()?.run_now(&id).await?;
    Ok(Json(json!({ "ok": true })))
}

async fn pause(State(state): State<AppStateRef>, Path(id): Path<String>) -> ApiResult<Value> {
    state.engine()?.set_paused(&id, true).await?;
    Ok(Json(json!({ "ok": true, "paused": true })))
}

async fn resume(State(state): State<AppStateRef>, Path(id): Path<String>) -> ApiResult<Value> {
    state.engine()?.set_paused(&id, false).await?;
    Ok(Json(json!({ "ok": true, "paused": false })))
}

// --------------------------------------------------------- groups and tags

async fn groups(State(state): State<AppStateRef>) -> ApiResult<Value> {
    let engine = state.engine()?;
    let config = engine.config();
    let statuses: HashMap<String, Status> = engine.group_statuses().into_iter().collect();
    let out: Vec<Value> = config
        .groups
        .iter()
        .map(|g| {
            let members: Vec<&str> = config
                .monitors
                .iter()
                .filter(|m| m.group.as_deref() == Some(g.id.as_str()))
                .map(|m| m.id.as_str())
                .collect();
            let children: Vec<&str> = config
                .groups
                .iter()
                .filter(|c| c.parent.as_deref() == Some(g.id.as_str()))
                .map(|c| c.id.as_str())
                .collect();
            json!({
                "id": g.id,
                "name": g.display_name(),
                "description": g.description,
                "parent": g.parent,
                "tags": g.tags,
                "status": statuses.get(&g.id).copied().unwrap_or(Status::Unknown),
                "monitors": members,
                "groups": children,
            })
        })
        .collect();
    Ok(Json(json!(out)))
}

async fn tags(State(state): State<AppStateRef>) -> ApiResult<Value> {
    let config = state.engine()?.config();
    let mut map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for m in &config.monitors {
        for t in &m.effective_tags {
            map.entry(t.as_str()).or_default().push(m.id.as_str());
        }
    }
    let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for g in &config.groups {
        for t in &g.tags {
            groups.entry(t.as_str()).or_default().push(g.id.as_str());
        }
    }
    let out: Vec<Value> = map
        .keys()
        .chain(groups.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|t| json!({ "tag": t, "monitors": map.get(t).cloned().unwrap_or_default(), "groups": groups.get(t).cloned().unwrap_or_default() }))
        .collect();
    Ok(Json(json!(out)))
}

async fn maintenance(State(state): State<AppStateRef>) -> ApiResult<Value> {
    let config = state.config();
    let now = now_ms();
    let out: Vec<Value> = config
        .maintenance
        .iter()
        .filter_map(|w| crate::maintenance::Window::parse(w).ok())
        .map(|w| {
            let until = w.active_until(now);
            let monitors: Vec<&str> = config.monitors.iter().filter(|m| w.applies_to(m)).map(|m| m.id.as_str()).collect();
            json!({ "id": w.id, "description": w.description, "active": until.is_some(), "active_until": until, "monitors": monitors })
        })
        .collect();
    Ok(Json(json!(out)))
}

// -------------------------------------------------------------- notifiers

async fn notifiers(State(state): State<AppStateRef>) -> ApiResult<Value> {
    let config = state.config();
    let out: Vec<Value> = config
        .notifiers
        .values()
        .map(|n| json!({ "id": n.id, "type": n.kind.type_name(), "events": n.events }))
        .collect();
    Ok(Json(json!(out)))
}

async fn test_notifier(State(state): State<AppStateRef>, Path(id): Path<String>) -> ApiResult<Value> {
    let engine = state.engine()?;
    match engine.dispatcher().test(&id).await {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(e) if e.starts_with("unknown notifier") => Err(not_found("notifier")),
        Err(e) => Err(ApiError(StatusCode::BAD_GATEWAY, e)),
    }
}

// ----------------------------------------------------------------- admin

async fn status(State(state): State<AppStateRef>) -> ApiResult<Value> {
    let engine = state.engine.read().ok().and_then(|e| e.clone());
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    if let Some(e) = &engine {
        for v in e.live().values() {
            *counts.entry(v.status.as_str()).or_default() += 1;
        }
    }
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "leader": engine.is_some(),
        "database": format!("{:?}", state.store.dialect()).to_lowercase(),
        "monitors": counts,
    })))
}

async fn reload(State(state): State<AppStateRef>) -> ApiResult<Value> {
    let (tx, rx) = oneshot::channel();
    state
        .reload
        .send(tx)
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "shutting down".into()))?;
    match rx.await {
        Ok(Ok(())) => Ok(Json(json!({ "ok": true }))),
        Ok(Err(e)) => Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY, e)),
        Err(_) => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "shutting down".into())),
    }
}

// ------------------------------------------------------------------ push

#[derive(Deserialize)]
struct PushQuery {
    status: Option<String>,
    msg: Option<String>,
    /// Latency in milliseconds.
    ping: Option<f64>,
}

async fn push(
    State(state): State<AppStateRef>,
    Path(token): Path<String>,
    Query(q): Query<PushQuery>,
) -> ApiResult<Value> {
    let outcome = match q.status.as_deref().unwrap_or("up") {
        "up" => Outcome::Up,
        "down" => Outcome::Down,
        "degraded" => Outcome::Degraded,
        other => return Err(ApiError(StatusCode::BAD_REQUEST, format!("unknown status {other:?}"))),
    };
    let latency = q
        .ping
        .filter(|p| p.is_finite() && *p >= 0.0)
        .map(|p| Duration::from_secs_f64(p.min(86_400_000.0) / 1000.0));
    let message: String = q
        .msg
        .unwrap_or_else(|| "push received".into())
        .chars()
        .take(512)
        .collect();
    let engine = state.engine()?;
    // Unknown and disabled tokens look the same to the caller.
    match engine
        .push(
            &token,
            PushReport {
                outcome,
                message,
                latency,
            },
        )
        .await
    {
        Ok(_) => Ok(Json(json!({ "ok": true }))),
        Err(CommandError::Busy) => Err(CommandError::Busy.into()),
        Err(_) => Err(not_found("push token")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_tokens() {
        assert!(token_eq("abcdefghijklmnop", "abcdefghijklmnop"));
        assert!(!token_eq("abcdefghijklmnop", "abcdefghijklmnoq"));
        assert!(!token_eq("abc", "abcd"));
    }

    #[test]
    fn summarizes_rollups() {
        let rows = vec![Rollup {
            bucket: 0,
            up: 8,
            degraded: 1,
            down: 1,
            maintenance: 2,
            latency_sum_us: 9000,
            latency_count: 9,
            ..Rollup::default()
        }];
        let s = summarize("24h", &rows);
        assert_eq!(s.uptime, Some(90.0));
        assert_eq!(s.avg_latency_ms, Some(1.0));
        assert_eq!(s.checks, 12);
        assert_eq!(summarize("7d", &[]).uptime, None);
    }
}
