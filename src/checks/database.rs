//! Connect to PostgreSQL or MySQL/MariaDB and run a query.

use std::time::Instant;

use sqlx::{Connection, MySqlConnection, PgConnection};

use super::CheckResult;
use super::util::fmt_latency;
use crate::config::DatabaseCheck;

#[derive(Clone, Copy)]
pub enum Engine {
    Postgres,
    Mysql,
}

pub struct DatabasePlan {
    engine: Engine,
    url: String,
    query: String,
}

impl DatabasePlan {
    pub fn prepare(c: &DatabaseCheck, engine: Engine) -> Result<Self, String> {
        let url = url::Url::parse(&c.url).map_err(|e| format!("invalid url: {e}"))?;
        let ok = match engine {
            Engine::Postgres => matches!(url.scheme(), "postgres" | "postgresql"),
            Engine::Mysql => matches!(url.scheme(), "mysql" | "mariadb"),
        };
        if !ok {
            return Err(format!("unexpected url scheme {:?}", url.scheme()));
        }
        Ok(Self {
            engine,
            url: c.url.replacen("mariadb://", "mysql://", 1),
            query: c.query.clone(),
        })
    }

    pub async fn run(&self) -> CheckResult {
        let start = Instant::now();
        let result = match self.engine {
            Engine::Postgres => {
                async {
                    let mut conn = PgConnection::connect(&self.url).await?;
                    sqlx::raw_sql(sqlx::AssertSqlSafe(self.query.clone()))
                        .execute(&mut conn)
                        .await?;
                    conn.close().await
                }
                .await
            }
            Engine::Mysql => {
                async {
                    let mut conn = MySqlConnection::connect(&self.url).await?;
                    sqlx::raw_sql(sqlx::AssertSqlSafe(self.query.clone()))
                        .execute(&mut conn)
                        .await?;
                    conn.close().await
                }
                .await
            }
        };
        let latency = start.elapsed();
        match result {
            Ok(()) => CheckResult::up(Some(latency), format!("query succeeded in {}", fmt_latency(latency))),
            Err(e) => CheckResult::down(e.to_string()),
        }
    }
}
