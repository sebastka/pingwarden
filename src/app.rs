//! Process lifecycle: database, API server, leader election, reloads, signals.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::api::{self, AppState, ReloadRequest};
use crate::auth::OidcVerifier;
use crate::config::{self, Config};
use crate::engine::Engine;
use crate::metrics::Metrics;
use crate::store::{LeaderLock, Store};

const LOCK_RETRY: Duration = Duration::from_secs(10);
const LOCK_CHECK: Duration = Duration::from_secs(5);

struct App {
    config_path: PathBuf,
    current: Arc<Config>,
    state: Arc<AppState>,
    store: Store,
    metrics: Metrics,
    shutdown: CancellationToken,
    reload_rx: mpsc::Receiver<ReloadRequest>,
}

pub async fn run(config_path: PathBuf, config: Config) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let metrics = Metrics::new();
    let store = connect_with_retry(&config).await?;
    store.migrate().await?;
    tracing::info!(dialect = ?store.dialect(), "database ready");

    let shutdown = CancellationToken::new();
    spawn_signal_handlers(shutdown.clone());

    let (reload_tx, reload_rx) = mpsc::channel::<ReloadRequest>(4);
    spawn_sighup(reload_tx.clone(), shutdown.clone());
    let oidc = match &config.server.auth.oidc {
        Some(o) => {
            let verifier = Arc::new(OidcVerifier::new(o.clone(), oidc_http_client(&config)?));
            tokio::spawn(verifier.clone().refresh_loop(shutdown.clone()));
            tracing::info!(issuer = %o.issuer, "OIDC access tokens accepted");
            Some(verifier)
        }
        None => None,
    };
    let state = Arc::new(AppState {
        config: RwLock::new(config.clone()),
        engine: RwLock::new(None),
        store: store.clone(),
        metrics: metrics.clone(),
        reload: reload_tx,
        oidc,
    });

    // Bind every listener before serving any, so a bad address fails fast.
    let mut bound = Vec::new();
    for l in config.server.effective_listeners() {
        let listener = tokio::net::TcpListener::bind(l.listen)
            .await
            .with_context(|| format!("cannot listen on {}", l.listen))?;
        bound.push((l, listener));
    }
    let mut servers = Vec::new();
    for (l, listener) in bound {
        let serve: Vec<&str> = l.serve.iter().map(|e| e.as_str()).collect();
        tracing::info!(listen = %l.listen, serve = %serve.join(","), "HTTP listener ready");
        let router = api::router(state.clone(), &l.serve);
        let server_shutdown = shutdown.clone();
        servers.push(tokio::spawn(async move {
            let serve =
                axum::serve(listener, router).with_graceful_shutdown(async move { server_shutdown.cancelled().await });
            if let Err(e) = serve.await {
                tracing::error!(error = %e, listen = %l.listen, "HTTP listener failed");
            }
        }));
    }

    let mut app = App {
        config_path,
        current: config,
        state,
        store,
        metrics,
        shutdown: shutdown.clone(),
        reload_rx,
    };
    app.elect_and_run().await;

    shutdown.cancel();
    for s in servers {
        let _ = s.await;
    }
    tracing::info!("bye");
    Ok(())
}

impl App {
    async fn elect_and_run(&mut self) {
        loop {
            let Some(lock) = self.acquire().await else { return };
            tracing::info!("leader lock acquired; starting checks");
            self.metrics.set_leader(true);
            let engine = match Engine::start(self.current.clone(), self.store.clone(), self.metrics.clone()).await {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(error = %format!("{e:#}"), "cannot start the engine");
                    self.metrics.set_leader(false);
                    lock.release().await;
                    tokio::select! {
                        _ = self.shutdown.cancelled() => return,
                        _ = tokio::time::sleep(LOCK_RETRY) => continue,
                    }
                }
            };
            self.set_engine(Some(engine.clone()));
            let (lock, lost) = self.lead(lock, &engine).await;
            self.set_engine(None);
            engine.shutdown().await;
            self.metrics.set_leader(false);
            if lost {
                // The connection is gone; dropping it is all that is left.
                drop(lock);
                continue;
            }
            lock.release().await;
            return;
        }
    }

    fn set_engine(&self, engine: Option<Arc<Engine>>) {
        if let Ok(mut e) = self.state.engine.write() {
            *e = engine;
        }
    }

    /// Run as leader until shutdown (`false`) or loss of the lock (`true`).
    async fn lead(&mut self, mut lock: LeaderLock, engine: &Arc<Engine>) -> (LeaderLock, bool) {
        let mut check = tokio::time::interval(LOCK_CHECK);
        check.reset();
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => return (lock, false),
                _ = check.tick() => {
                    let alive = tokio::time::timeout(LOCK_CHECK, lock.check()).await;
                    if let Err(e) = alive.unwrap_or_else(|_| Err(anyhow::anyhow!("timed out"))) {
                        tracing::error!(error = %format!("{e:#}"), "lost the leader lock connection; stopping checks");
                        return (lock, true);
                    }
                }
                Some(req) = self.reload_rx.recv() => {
                    let result = match self.load().await {
                        Ok(new) => {
                            let applied = engine.apply(new.clone()).await.map_err(|e| format!("{e:#}"));
                            if applied.is_ok() {
                                self.current = new;
                            }
                            applied
                        }
                        Err(e) => Err(e),
                    };
                    if let Err(e) = &result {
                        tracing::error!(error = %e, "reload failed; keeping the current configuration");
                    }
                    let _ = req.send(result);
                }
            }
        }
    }

    /// Wait for the leader lock, serving reloads meanwhile. `None` on shutdown.
    async fn acquire(&mut self) -> Option<LeaderLock> {
        let mut announced = false;
        loop {
            match self.store.try_lock(&self.current.database.lock_name).await {
                Ok(Some(lock)) => return Some(lock),
                Ok(None) if !announced => {
                    tracing::info!("another instance holds the leader lock; standing by");
                    announced = true;
                }
                Ok(None) => {}
                Err(e) => tracing::error!(error = %format!("{e:#}"), "cannot take the leader lock"),
            }
            let deadline = tokio::time::sleep(LOCK_RETRY);
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    _ = self.shutdown.cancelled() => return None,
                    _ = &mut deadline => break,
                    Some(req) = self.reload_rx.recv() => {
                        let result = self.load().await.map(|c| self.current = c);
                        let _ = req.send(result);
                    }
                }
            }
        }
    }

    /// Load and validate the configuration, and publish it to the API.
    async fn load(&self) -> Result<Arc<Config>, String> {
        let config = load_blocking(&self.config_path).await?;
        if let Ok(mut c) = self.state.config.write() {
            *c = config.clone();
        }
        Ok(config)
    }
}

async fn load_blocking(path: &Path) -> Result<Arc<Config>, String> {
    let p = path.to_owned();
    tokio::task::spawn_blocking(move || config::load(&p))
        .await
        .map_err(|e| e.to_string())?
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

/// HTTP client for discovery and JWKS, trusting `tls.ca_files` too (for
/// providers behind an internal CA).
fn oidc_http_client(config: &Config) -> anyhow::Result<reqwest::Client> {
    let (_, extra) = crate::checks::util::load_roots(&config.tls)?;
    let certs: Vec<reqwest::Certificate> = extra
        .iter()
        .filter_map(|c| reqwest::Certificate::from_der(c).ok())
        .collect();
    let mut b = reqwest::Client::builder()
        .user_agent(concat!("Pingwarden/", env!("CARGO_PKG_VERSION")))
        .pool_max_idle_per_host(1);
    if !certs.is_empty() {
        b = b.tls_certs_merge(certs);
    }
    Ok(b.build()?)
}

async fn connect_with_retry(config: &Config) -> anyhow::Result<Store> {
    let mut delay = Duration::from_secs(1);
    for attempt in 0.. {
        match Store::connect(&config.database).await {
            Ok(s) => return Ok(s),
            Err(e) if attempt < 30 => {
                tracing::warn!(error = %format!("{e:#}"), retry_in = ?delay, "database unavailable");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

fn spawn_signal_handlers(shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "cannot install the SIGTERM handler");
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => tracing::info!("SIGTERM received, shutting down"),
            _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received, shutting down"),
        }
        shutdown.cancel();
    });
}

/// SIGHUP triggers the same reload as `POST /api/v1/reload`.
fn spawn_sighup(reload: mpsc::Sender<ReloadRequest>, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let Ok(mut hup) = signal(SignalKind::hangup()) else {
            return;
        };
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                received = hup.recv() => {
                    if received.is_none() {
                        return;
                    }
                    tracing::info!("SIGHUP received, reloading configuration");
                    let (tx, rx) = oneshot::channel();
                    if reload.send(tx).await.is_err() {
                        return;
                    }
                    let _ = rx.await;
                }
            }
        }
    });
}
