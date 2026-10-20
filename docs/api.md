# API

The machine-readable contract is [`openapi.yaml`](openapi.yaml) (OpenAPI 3.1);
generate the UI client from it, for example with `openapi-typescript`.

- **Authentication:** `Authorization: Bearer <token>` with a token from
  `server.api_tokens`. `read` tokens may call GET endpoints; `admin` tokens
  may call everything. `/healthz`, `/readyz` and `/api/v1/push/{token}` are
  open, and `/metrics` is open unless `server.metrics_token` is set.
- **Time:** timestamps are milliseconds since the Unix epoch (UTC). Ranges
  take `from` (inclusive) and `to` (exclusive); lists are newest first and
  capped by `limit` (default 500, at most 10,000).
- **Errors:** `{"error": "…"}` with a meaningful status code. On a standby
  instance, live endpoints return 503.

| Method | Path | Scope | Purpose |
|---|---|---|---|
| GET | `/healthz`, `/readyz` | – | Probes |
| GET | `/metrics` | optional token | Prometheus metrics |
| GET | `/api/v1/status` | read | Version, leadership, monitors per status |
| GET | `/api/v1/monitors?tag=&group=&status=&type=` | read | Monitors and their live state |
| GET | `/api/v1/monitors/{id}` | read | One monitor |
| GET | `/api/v1/monitors/{id}/heartbeats` | read | Raw results |
| GET | `/api/v1/monitors/{id}/events` | read | Status transitions |
| GET | `/api/v1/monitors/{id}/uptime` | read | Uptime and latency over 24h, 7d, 30d, 365d |
| GET | `/api/v1/monitors/{id}/rollups?resolution=hour\|day` | read | Chart data |
| POST | `/api/v1/monitors/{id}/check` | admin | Run now |
| POST | `/api/v1/monitors/{id}/pause`, `/resume` | admin | Pause or resume (persisted) |
| GET | `/api/v1/groups` | read | Groups and their aggregated status |
| GET | `/api/v1/tags` | read | Tags and what carries them |
| GET | `/api/v1/maintenance` | read | Maintenance windows, active or not |
| GET | `/api/v1/events` | read | Transitions of every monitor |
| GET | `/api/v1/notifiers` | read | Notifiers (no secrets) |
| POST | `/api/v1/notifiers/{id}/test` | admin | Send a test notification |
| GET | `/api/v1/notifications` | read | Delivery log |
| POST | `/api/v1/reload` | admin | Reload the configuration |
| GET, POST | `/api/v1/push/{token}?status=&msg=&ping=` | push token | Push monitor results |

Example:

```sh
curl -fsS -H "Authorization: Bearer $TOKEN" "http://localhost:8080/api/v1/monitors?tag=prod&status=down"
```
