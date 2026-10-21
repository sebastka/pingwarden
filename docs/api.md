# API

The machine-readable contract is [`openapi.yaml`](openapi.yaml) (OpenAPI 3.1);
generate the UI client from it, for example with `openapi-typescript`.

- **Authentication:** `Authorization: Bearer <token>`, with either a static
  token from `server.api_tokens` or an OpenID Connect access token (JWT)
  when `server.auth.oidc` is set (see the [configuration
  reference](configuration.md#openid-connect)). `read` access allows GET
  endpoints; `admin` allows everything. `/healthz`, `/readyz` and
  `/api/v1/push/{token}` are open, and `/metrics` is open unless
  `server.metrics_token` is set.
- **Status codes:** 401 for a missing, invalid or expired token; 403 for a
  valid token without the needed access; 503 when the provider's signing
  keys cannot be fetched.
- **Browsers:** UIs on another origin need `server.cors`.
- **Time:** timestamps are milliseconds since the Unix epoch (UTC). Ranges
  take `from` (inclusive) and `to` (exclusive); lists are newest first and
  capped by `limit` (default 500, at most 10,000).
- **Errors:** `{"error": "…"}` with a meaningful status code. On a standby
  instance, live endpoints return 503.
- **Request bodies** (actions that take options) are JSON, sent with
  `Content-Type: application/json`; an empty body means "no options".

| Method | Path | Scope | Purpose |
|---|---|---|---|
| GET | `/healthz`, `/readyz` | – | Probes |
| GET | `/metrics` | optional token | Prometheus metrics |
| GET | `/api/v1/status` | read | Version, leadership, monitors per status |
| GET | `/api/v1/me` | read | The caller: name, kind of credential, scope |
| GET | `/api/v1/stream` | read | Live changes (server-sent events) |
| GET | `/api/v1/monitors?tag=&group=&status=&type=` | read | Monitors and their live state |
| GET | `/api/v1/monitors/{id}` | read | One monitor |
| GET | `/api/v1/monitors/{id}/config` | read | Effective settings, without secrets |
| GET | `/api/v1/monitors/{id}/heartbeats` | read | Raw results |
| GET | `/api/v1/monitors/{id}/events` | read | Status transitions |
| GET | `/api/v1/monitors/{id}/uptime` | read | Uptime and latency over 24h, 7d, 30d, 365d |
| GET | `/api/v1/monitors/{id}/rollups?resolution=hour\|day` | read | Chart data |
| GET | `/api/v1/rollups?resolution=hour\|day&tag=&group=` | read | Chart data of every monitor at once |
| POST | `/api/v1/monitors/{id}/check` | admin | Run now |
| POST | `/api/v1/monitors/{id}/pause`, `/resume` | admin | Pause or resume (persisted) |
| POST | `/api/v1/monitors/{id}/ack`, `/unack` | admin | Acknowledge a problem: no reminders until it is over |
| POST | `/api/v1/monitors/{id}/silence`, `/unsilence` | admin | Mute its notifications for up to 7 days |
| GET | `/api/v1/groups` | read | Groups and their aggregated status |
| GET | `/api/v1/tags` | read | Tags and what carries them |
| GET | `/api/v1/maintenance` | read | Maintenance windows, active or not |
| POST | `/api/v1/maintenance` | admin | Start a maintenance window (at most 30 days) |
| POST | `/api/v1/maintenance/{id}/end` | admin | End a window created through the API |
| GET | `/api/v1/events` | read | Transitions of every monitor |
| GET | `/api/v1/notifiers` | read | Notifiers (no secrets) |
| POST | `/api/v1/notifiers/{id}/test` | admin | Send a test notification |
| GET | `/api/v1/notifications?monitor=&notifier=&success=&event=` | read | Delivery log |
| POST | `/api/v1/reload` | admin | Reload the configuration |
| GET, POST | `/api/v1/push/{token}?status=&msg=&ping=` | push token | Push monitor results |

Example:

```sh
curl -fsS -H "Authorization: Bearer $TOKEN" "http://localhost:8080/api/v1/monitors?tag=prod&status=down"
```

## Live stream

`GET /api/v1/stream` answers `text/event-stream` and sends one event per
change, with JSON data:

| `event:` | `data:` |
|---|---|
| `transition` | A status change, as listed by `/events` (with its `id`) |
| `notification` | A delivery, as listed by `/notifications` (with its `id`) |
| `monitor` | `{"id": "…"}`: the live state changed without a transition (paused, resumed, acknowledged, silenced…) |
| `maintenance` | `{}`: a window was created, ended, started or stopped |
| `reload` | `{}`: the configuration was reloaded |
| `resync` | `{}`: this client fell behind and missed changes; read everything again |

A `: keepalive` comment is sent every 15 s. Transitions and deliveries are
sent once they are stored, about a second after they happen. At most 64
streams are open at once (more: 503). A stream ends when the instance stops
leading or shuts down; reconnect (browsers' `EventSource` does).

```sh
curl -N -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/stream
```

## Acknowledge, silence, maintenance

```sh
# Acknowledge (only a down, pending or degraded monitor; 409 otherwise)
curl -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"comment": "on it"}' http://localhost:8080/api/v1/monitors/web/ack
# Silence every notification about it for 2 hours (or {"until": <ms>}; at most 7 days)
curl -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"duration": "2h"}' http://localhost:8080/api/v1/monitors/web/silence
# Maintenance for the web group, starting now, for one hour
curl -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"id": "router-swap", "groups": ["web"], "duration": "1h"}' http://localhost:8080/api/v1/maintenance
curl -X POST -H "Authorization: Bearer $ADMIN" http://localhost:8080/api/v1/maintenance/router-swap/end
```

- An acknowledgement stops reminders until the monitor is up again, when it
  is cleared; `unack` withdraws it.
- A silence suppresses every notification about the monitor until it ends;
  transitions meanwhile record `suppressed_reason: "silenced by <who> until
  <time>"`, and a status still different from the last notified one is
  notified when the silence ends.
- Maintenance windows created through the API (`source: "api"`) work like
  one-off windows of the configuration. They are stored in the database,
  listed for a week after they end, and only they can be ended through the
  API. Body: `id` (optional), `description`, a selection (`monitors`,
  `groups`, `tags`, `all`), `start` (ms, default now, at most 30 days ahead),
  and `end` (ms) or `duration`; at most 30 days long.
