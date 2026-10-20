//! Pingwarden: headless, configuration-as-code uptime monitor.

use pingwarden::{app, config, store};

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Configuration file, or directory of *.yaml files.
    #[arg(
        short,
        long,
        env = "PINGWARDEN_CONFIG",
        default_value = "/etc/pingwarden",
        global = true
    )]
    config: PathBuf,
    /// Log format.
    #[arg(long, env = "PINGWARDEN_LOG_FORMAT", default_value = "text", value_parser = ["text", "json"], global = true)]
    log_format: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the monitor (default).
    Run,
    /// Validate the configuration and exit.
    Validate,
    /// Apply database migrations and exit.
    Migrate,
    /// Probe the local `/healthz`, for container health checks.
    Healthcheck {
        /// Address to probe; by default the listener serving `health` in the
        /// configuration (127.0.0.1:8080 if it cannot be read).
        #[arg(long)]
        addr: Option<String>,
    },
}

fn init_tracing(format: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("PINGWARDEN_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    if format == "json" {
        builder.json().flatten_event(true).init();
    } else {
        builder.init();
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Run) {
        Command::Healthcheck { addr } => match addr.or_else(|| health_addr(&cli.config)) {
            Some(addr) => healthcheck(&addr),
            None => {
                eprintln!("no listener serves the `health` endpoints; pass --addr");
                ExitCode::FAILURE
            }
        },
        Command::Validate => match config::load(&cli.config) {
            Ok(c) => {
                println!(
                    "configuration is valid: {} monitors, {} groups, {} notifiers, {} maintenance windows",
                    c.monitors.len(),
                    c.groups.len(),
                    c.notifiers.len(),
                    c.maintenance.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        cmd @ (Command::Run | Command::Migrate) => {
            init_tracing(&cli.log_format);
            let config = match config::load(&cli.config) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            if rustls::crypto::ring::default_provider().install_default().is_err() {
                tracing::debug!("a TLS crypto provider was already installed");
            }
            let runtime = build_runtime(config.runtime.worker_threads);
            let runtime = match runtime {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "cannot start the async runtime");
                    return ExitCode::FAILURE;
                }
            };
            let result = runtime.block_on(async move {
                match cmd {
                    Command::Migrate => {
                        let store = store::Store::connect(&config.database).await?;
                        store.migrate().await?;
                        tracing::info!("migrations applied");
                        Ok(())
                    }
                    _ => app::run(cli.config, config).await,
                }
            });
            // Do not wait for lingering blocking tasks (DNS, SMTP) on exit.
            runtime.shutdown_timeout(Duration::from_secs(5));
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!("{e:#}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn build_runtime(workers: usize) -> std::io::Result<tokio::runtime::Runtime> {
    let mut b = if workers <= 1 {
        tokio::runtime::Builder::new_current_thread()
    } else {
        let mut b = tokio::runtime::Builder::new_multi_thread();
        b.worker_threads(workers);
        b
    };
    b.enable_all()
        .max_blocking_threads(4)
        .thread_stack_size(512 * 1024)
        .thread_name("pingwarden")
        .build()
}

/// Local address of the listener serving `/healthz`.
fn health_addr(path: &std::path::Path) -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    let Ok(c) = config::load(path) else {
        return Some("127.0.0.1:8080".into());
    };
    let l = c
        .server
        .effective_listeners()
        .into_iter()
        .find(|l| l.serve.contains(&config::Endpoints::Health))?;
    let ip = match l.listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    Some(SocketAddr::new(ip, l.listen.port()).to_string())
}

/// Minimal HTTP GET of /healthz, without any extra dependency.
fn healthcheck(addr: &str) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(_) => return ExitCode::FAILURE,
    };
    let ok = rt.block_on(async {
        let probe = async {
            let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
            s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await
                .ok()?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.ok()?;
            Some(buf.starts_with(b"HTTP/1.1 200") || buf.starts_with(b"HTTP/1.0 200"))
        };
        tokio::time::timeout(Duration::from_secs(5), probe)
            .await
            .ok()
            .flatten()
            .unwrap_or(false)
    });
    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
