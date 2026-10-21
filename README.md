# Pingwarden

A headless uptime monitor written in Rust, an alternative to Uptime Kuma for
people who keep their infrastructure in code.

- **Configuration as code.** Monitors, groups, notifiers and maintenance
  windows live in YAML files. `${ENV}` and `${file:…}` provide secrets, and the
  configuration reloads without a restart.
- **State in SQL.** History is stored in PostgreSQL or MariaDB: heartbeats,
  hourly and daily rollups, transitions and the notification log, each with
  its own retention.
- **Many checks.** ICMP, TCP (banners, TLS), UDP (with explicit semantics),
  HTTP(S) (status, keyword, JSON), TLS certificates (with STARTTLS for SMTP,
  IMAP, POP3, FTP, PostgreSQL and LDAP), DNS, NTP, PostgreSQL, MySQL/MariaDB,
  and push (heartbeat) monitors.
- **Alerting that does not cry wolf.** Failure and recovery thresholds,
  dependencies, flap detection, maintenance windows and reminders. Restarts
  neither re-notify nor forget an outage.
- **Notifications:** webhook, ntfy, Gotify, Matrix, Discord, Slack, Telegram,
  Pushover and email.
- **Groups and tags.** Groups nest, pass down settings and tags, and have an
  aggregated status.
- **Headless.** A JSON API ([OpenAPI](docs/openapi.yaml)) for UIs, with a
  live event stream (SSE), plus Prometheus `/metrics`.
- **Runtime actions** without touching the configuration: run now, pause,
  acknowledge an outage (no reminders), silence a monitor, start a short
  maintenance window. Each is audited with the caller.
- **Small.** About 5 MiB of RAM, measured with 15 monitors of every type, and an 8 MB image
  holding one static binary. The image is built on Docker Hardened Images and runs unprivileged,
  read-only and without any capability.
- **Highly available.** Instances sharing a database elect a leader; only the
  leader runs checks.

## Quick start

```sh
cd deploy
POSTGRES_PASSWORD=$(openssl rand -hex 16) PINGWARDEN_ADMIN_TOKEN=$(openssl rand -hex 24) \
  docker compose up -d
curl -s -H "Authorization: Bearer $PINGWARDEN_ADMIN_TOKEN" localhost:8080/api/v1/monitors
```

Edit `deploy/config/*.yaml`, then `docker kill -s HUP pingwarden`.

```yaml
groups:
  - id: web
    tags: [public]
    defaults: { notify: [ntfy] }

monitors:
  - id: website
    type: http
    url: https://example.com/
    group: web
    keyword: Example Domain
  - id: website-cert
    type: tls
    host: example.com
    group: web
    expiry_warning: 21d
```

## Documentation

- [Configuration reference](docs/configuration.md)
- [Checks](docs/checks.md)
- [API](docs/api.md) and [OpenAPI spec](docs/openapi.yaml)
- [Deployment](docs/deployment.md): Docker, Kubernetes, ICMP without
  privileges, metrics
- [Design decisions](DECISIONS.md)
- [Full example configuration](examples/config.yaml)

## Command line

```
pingwarden [--config PATH] [--log-format text|json] [run|validate|migrate|healthcheck]
```

| Variable | Purpose |
|---|---|
| `PINGWARDEN_CONFIG` | Configuration file or directory (default `/etc/pingwarden`) |
| `PINGWARDEN_LOG` | Log filter, e.g. `info,pingwarden=debug` |
| `PINGWARDEN_LOG_FORMAT` | `text` or `json` |

## Development

The toolchain is Rust 1.96, the version shipped by the hardened build image.

```sh
cargo test                       # unit tests; DB tests are skipped
PINGWARDEN_TEST_POSTGRES=postgres://pw:pw@localhost:5432/pw \
PINGWARDEN_TEST_MARIADB=mariadb://pw:pw@localhost:3306/pw \
  cargo test                     # including PostgreSQL and MariaDB tests
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
yamllint --strict .
cargo deny check
docker build -t pingwarden:dev . # needs `docker login dhi.io`
```

## License

[MIT](LICENSE)
