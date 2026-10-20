//! Helpers for integration tests that need a database.
//!
//! Set `PINGWARDEN_TEST_POSTGRES` and/or `PINGWARDEN_TEST_MARIADB` to
//! connection URLs; tests are skipped for unset variables.

#![allow(dead_code)]

use pingwarden::config::{DatabaseConfig, Dur};
use pingwarden::store::Store;

pub fn database_urls() -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for (name, var) in [
        ("postgres", "PINGWARDEN_TEST_POSTGRES"),
        ("mariadb", "PINGWARDEN_TEST_MARIADB"),
    ] {
        match std::env::var(var) {
            Ok(url) if !url.is_empty() => out.push((name, url)),
            _ => eprintln!("{var} is not set; skipping {name}"),
        }
    }
    out
}

pub fn db_config(url: &str) -> DatabaseConfig {
    DatabaseConfig {
        url: url.to_owned(),
        max_connections: 4,
        connect_timeout: Dur::secs(10),
        lock_name: unique("lock"),
    }
}

pub async fn store(url: &str) -> Store {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let store = Store::connect(&db_config(url)).await.expect("connect");
    store.migrate().await.expect("migrate");
    store
}

/// A name unique to this test run, so tests can share a database.
pub fn unique(prefix: &str) -> String {
    format!("{prefix}-{}-{:08x}", std::process::id(), rand::random::<u32>())
}
