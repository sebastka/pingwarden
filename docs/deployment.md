# Deployment

Pingwarden is one static binary in a container image
(`ghcr.io/sebastka/pingwarden`). Built on Docker Hardened Images, it runs as
user 65532 with a read-only root filesystem and needs no capability. It needs
a PostgreSQL or MariaDB database and its configuration directory.

## Docker Compose

[`deploy/docker-compose.yaml`](../deploy/docker-compose.yaml) runs Pingwarden
with PostgreSQL:

```sh
cd deploy
POSTGRES_PASSWORD=$(openssl rand -hex 16) PINGWARDEN_ADMIN_TOKEN=$(openssl rand -hex 24) docker compose up -d
docker compose logs -f pingwarden
docker kill -s HUP pingwarden   # reload deploy/config/*.yaml
```

## Kubernetes

[`deploy/kubernetes.yaml`](../deploy/kubernetes.yaml) is a minimal Deployment
and Service with the restricted pod security profile. Mount the configuration
from a ConfigMap. ConfigMap updates are not picked up automatically; trigger a
reload with `POST /api/v1/reload`, or let a reloader restart the pod.

## ICMP

Ping without privileges uses an ICMP *datagram* socket. The kernel allows it
when the process's group falls within `net.ipv4.ping_group_range`.
Alternatively, `CAP_NET_RAW` allows a raw socket. Tested on rootless Docker:

| Setup | Works |
|---|---|
| `--sysctl net.ipv4.ping_group_range="65532 65532"`, no capability | ✅ recommended |
| `--cap-add NET_RAW --user 0` (root in the container, only that capability) | ✅ |
| `--cap-add NET_RAW`, default user 65532 | ❌ Docker gives non-root users no ambient capabilities, and `no-new-privileges` blocks file capabilities |
| nothing | ❌ on rootless Docker. Rootful Docker usually sets a wide `ping_group_range` itself |

- **Docker:** `sysctls: {net.ipv4.ping_group_range: "65532 65532"}`.
  Rootless Docker refuses `0 2147483647`, because the user namespace does not
  map that whole range.
- **Kubernetes:** `net.ipv4.ping_group_range` is a "safe" sysctl, allowed by
  default. Set it in `spec.securityContext.sysctls`.
- **`--network host`:** the host's own sysctl applies.

Without either setup, ICMP monitors are down with "cannot open ICMP socket" and
every other check keeps working.

## Database

Create a database and a user that owns it. Migrations run at start.

```sql
-- PostgreSQL
CREATE USER pingwarden WITH PASSWORD '…';
CREATE DATABASE pingwarden OWNER pingwarden;

-- MariaDB
CREATE DATABASE pingwarden CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'pingwarden'@'%' IDENTIFIED BY '…';
GRANT ALL ON pingwarden.* TO 'pingwarden'@'%';
```

Disk usage is about 150 bytes per heartbeat including indexes. For example,
100 monitors at 60 s with the default 14-day retention keep roughly 2 million
heartbeats, about 300 MB. Uptime and latency history comes from rollups and is
not affected by heartbeat retention.

## Several instances

Instances sharing a database elect a leader with an advisory lock (see
DECISIONS.md D4). Only the leader runs checks; standbys answer the API with
503 and take over within about 10 s. `/readyz` is ready whenever the database
is reachable; `/readyz?role=leader` is ready on the leader only.

## Listeners

By default, one listener on `0.0.0.0:8080` serves everything: probes,
metrics, the API and push. It is plain HTTP; put a TLS-terminating proxy in
front of anything reachable beyond a trusted network.

`server.listeners` assigns the endpoint groups `health`, `metrics`, `api` and
`push` to separate addresses (see the [configuration
reference](configuration.md#listeners)). Each can then be exposed, firewalled
or routed on its own, for example only `push` through the internet-facing
ingress, with metrics scraped on an internal port. Expose the matching ports
in Docker or Kubernetes, and point probes at the port serving `health`. The
image's `HEALTHCHECK` finds that port by itself.

## Health and observability

| Endpoint | Purpose |
|---|---|
| `/healthz` | Liveness, always 200 while the process serves HTTP. `pingwarden healthcheck` probes it (Docker `HEALTHCHECK`). |
| `/readyz` | Database reachable (`?role=leader`: and leader). |
| `/metrics` | Prometheus/OpenMetrics; optionally protected by `server.metrics_token`. |

Main metrics:

- `pingwarden_monitor_status`: 0 down, 1 up, 2 pending, 3 maintenance,
  4 degraded, 5 paused, 6 unknown.
- `pingwarden_monitor_up`
- `pingwarden_monitor_latency_seconds`
- `pingwarden_monitor_checks_total{outcome}`
- `pingwarden_monitor_cert_expiry_timestamp_seconds`
- `pingwarden_group_status`
- `pingwarden_notifications_total{result}`
- `pingwarden_heartbeats_dropped_total`
- `pingwarden_database_errors_total`
- `pingwarden_leader`

`pingwarden_monitor_info{name,monitor_type,group,tags}` carries the metadata,
for joins such as:

```promql
pingwarden_monitor_up == 0
  and on (monitor) pingwarden_monitor_info{tags=~".*,prod,.*"}
```

Logs go to stdout. Set the format with `PINGWARDEN_LOG_FORMAT=json` and the
level with `PINGWARDEN_LOG=info,pingwarden=debug`.

## Resource use

Measured at 4.7 MiB RSS with 15 monitors of all types; the image is 8.2 MB. A 64 MiB memory limit
leaves ample headroom. For the smallest footprint set
`runtime.worker_threads: 1`.
