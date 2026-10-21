# Configuration reference

Pingwarden reads its configuration from YAML. `--config` (or
`PINGWARDEN_CONFIG`, default `/etc/pingwarden`) names either a file or a
directory. For a directory, every `*.yaml`/`*.yml` file is loaded in name order
and merged; hidden files are skipped.

- `server`, `database`, `retention`, `defaults`, `tls` and `runtime` may each
  appear in one file only.
- `notifiers` entries are merged across files (ids must be unique).
- `groups`, `monitors` and `maintenance` lists are concatenated.

Check a configuration without starting anything:

```sh
pingwarden validate --config /etc/pingwarden
```

Reload a running instance with `SIGHUP` or `POST /api/v1/reload` (admin
token). An invalid configuration is rejected and the current one kept.

A complete example is in [`examples/config.yaml`](../examples/config.yaml).

## Conventions

- **Durations:** `500ms`, `30s`, `5m`, `1h30m`, `14d`, `2w`, or an integer
  number of seconds. `0` means "never" or "forever" where noted.
- **Substitution** applies to every string value:

  | Syntax | Result |
  |---|---|
  | `${VAR}` | the environment variable; an error if unset |
  | `${VAR:-default}` | the variable, or `default` when unset |
  | `${file:/run/secrets/x}` | the file's content, without a trailing newline |
  | `$$` | a literal `$` |

  A value that is exactly one reference, such as `port: ${PORT}`, is typed
  automatically.
- **Booleans** are `true`/`false` only (YAML 1.2): `no`, `on` and `y` are
  strings.
- **Unknown keys are errors.** Errors give the file and the path, such as
  `monitors[3].port`.
- **Ids** (monitors, groups, notifiers, maintenance) use letters, digits and
  `_-.`, start with a letter or digit, and are at most 128 characters long.
- **Tags** are 1-64 characters, without whitespace or commas, e.g. `prod` or
  `team:infra`.

## `server`

| Key | Default | Description |
|---|---|---|
| `listen` | `0.0.0.0:8080` | Shorthand for a single listener serving every endpoint. |
| `listeners` | unset | List of `{listen, serve}`; replaces `listen` (set one or the other). |
| `api_tokens` | `[]` | `{name, token, scope}` entries. `scope` is `read` (GET endpoints) or `admin` (everything). Tokens are at least 16 characters long. |
| `anonymous_read` | `false` | Serve read endpoints without a token. |
| `metrics_token` | unset | Bearer token required by `/metrics`; it is open when unset. |
| `auth.oidc` | unset | Accept access tokens from an OpenID Connect provider; see below. |
| `cors` | unset | Let browser UIs on other origins call the API; see below. |

`/healthz`, `/readyz` and `/api/v1/push/{token}` never need an API token.

### OpenID Connect

With `server.auth.oidc`, the API also accepts JWT access tokens from your
identity provider (Keycloak, Authentik, Zitadel, …). Static `api_tokens`
keep working, for scripts and simple setups. Pingwarden never issues
tokens: browser UIs sign users in with the provider (authorization code with
PKCE), and machines use the client-credentials grant.

```yaml
server:
  auth:
    oidc:
      issuer: https://auth.example.com/realms/home   # exactly the tokens' `iss`
      audience: pingwarden          # or a list; a token needs one of them in `aud`
      claim: realm_access.roles     # where permissions are, see below
      read: [pingwarden-read]       # values granting read access
      admin: [pingwarden-admin]     # values granting admin (and read) access
```

| Key | Default | Description |
|---|---|---|
| `issuer` | required | `https://`; `http://` only for `localhost`. |
| `audience` | required | String or list. |
| `claim` | `scope` | A space-separated string (`scope`) or a list (`groups`, `roles`). Dots descend into objects: `realm_access.roles`, `resource_access.pingwarden.roles`. |
| `read`, `admin` | `[]` | At least one must be set. A token matching neither is rejected with 403. |
| `jwks_url` | discovered | Signing keys URL; by default read from `{issuer}/.well-known/openid-configuration`. |
| `jwks_refresh` | `1h` | Key refresh period. A token naming an unknown key also triggers a refresh, at most every 30 s. |
| `leeway` | `60s` | Clock skew tolerated on `exp` and `nbf`. |

- **Accepted signatures:** RS256/384/512, PS256/384/512, ES256, ES384 and
  EdDSA. Unsigned (`none`) and shared-secret (HS*) tokens are refused.
- **Required claims:** tokens need `exp`. `iss`, `aud` and `nbf` (when
  present) are checked.
- **Audit:** admin actions are logged with the caller. For OIDC tokens that
  is `oidc:<name>`, where the name comes from `preferred_username`, else
  `client_id`, else `sub`. For static tokens it is `token:<name>`.
- **Internal CAs:** a provider behind an internal CA needs it in
  `tls.ca_files`.

Provider notes:
- **Keycloak** puts realm roles in `realm_access.roles`, and client roles in
  `resource_access.<client>.roles`. Its access tokens carry
  `aud: account` unless you add an *audience* mapper (`Included Custom
  Audience: pingwarden`) to the client, or to a client scope it uses.
- **Authentik** puts groups in `groups` (scope `profile`). Its audience is
  the provider's client id.

### CORS

A browser UI served from another origin needs `server.cors`:

```yaml
server:
  cors:
    allowed_origins: ["https://pingwarden-ui.example.com", "http://localhost:5173"]
    max_age: 10m   # preflight cache
```

Origins are `scheme://host[:port]` without path, or `*` alone for any. Only
`GET`, `HEAD` and `POST` with the `Authorization` and `Content-Type` headers
are allowed. Credentials (cookies) are never involved: the API takes bearer
tokens only.

### Listeners

The HTTP endpoints form four groups, and each listener serves the groups listed
in its `serve` (all of them when `serve` is omitted):

| Group | Paths |
|---|---|
| `health` | `/healthz`, `/readyz` |
| `metrics` | `/metrics` |
| `api` | `/api/v1/…` except push |
| `push` | `/api/v1/push/{token}` |

Paths of groups a listener does not serve answer 404 there. For example, push
reachable from the internet (through a proxy), the UI API internal, and probes
and metrics only on the pod network:

```yaml
server:
  listeners:
    - listen: 0.0.0.0:8080
      serve: [push]
    - listen: 0.0.0.0:8081
      serve: [api]
    - listen: 0.0.0.0:9090
      serve: [health, metrics]
```

A group may be served by several listeners or by none (for example, no `push`
when there is no push monitor). Two listeners cannot share an address.
`pingwarden healthcheck` probes the first listener serving `health`. Listener
changes take effect at the next restart, not on reload.

## `database`

| Key | Default | Description |
|---|---|---|
| `url` | required | `postgres://user:pass@host/db` or `mariadb://user:pass@host/db` (`mysql://` is accepted). TLS options go in the URL (`?sslmode=verify-full`, `?ssl-mode=VERIFY_IDENTITY`). |
| `max_connections` | `4` | Pool size; at least 2 are used. |
| `connect_timeout` | `10s` | |
| `lock_name` | `pingwarden` | Advisory lock electing the active instance. Use different names for independent deployments sharing a database. |

The schema is migrated automatically at start (`pingwarden migrate` runs it
alone).

## `retention`

| Key | Default | Description |
|---|---|---|
| `heartbeats` | `14d` | Raw check results. |
| `hourly` | `400d` | Hourly rollups. |
| `daily` | `0` (forever) | Daily rollups. |
| `events` | `400d` | Status transitions. |
| `notifications` | `90d` | Delivery log. |
| `removed_monitors` | `30d` | How long the history of monitors removed from the configuration is kept. |
| `cleanup_interval` | `1h` | |

## `defaults`

Fallback values for monitors. Groups can override them for their members.

| Key | Default | Description |
|---|---|---|
| `interval` | `60s` | Time between checks. |
| `timeout` | `10s` | Per check, at most `interval`. |
| `failure_threshold` | `3` | Consecutive failures before `down` (`pending` before that). |
| `recovery_threshold` | `1` | Consecutive successes before a down monitor is `up` again. |
| `notify` | `[]` | Notifier ids. |
| `renotify_every` | `0` | Reminder interval while down; `0` disables reminders. |
| `notify_degraded` | `true` | Notify up↔degraded changes. |
| `flapping` | unset | `{window: 1h, max_transitions: 6}` enables flap detection. |

## `tls`

| Key | Default | Description |
|---|---|---|
| `ca_files` | `[]` | Extra PEM CA bundles trusted by every TLS-based check. |
| `disable_system_roots` | `false` | Trust only `ca_files`. |

## `runtime`

| Key | Default | Description |
|---|---|---|
| `worker_threads` | `2` | `1` selects the single-threaded runtime (smallest footprint). |
| `max_concurrent_checks` | `64` | |

## `notifiers`

A mapping of id to notifier. Every notifier has a `type` and an optional
`events` list, which limits it to some of `down`, `up`, `degraded`,
`reminder`, `flapping` and `test`.

| `type` | Keys |
|---|---|
| `webhook` | `url`, `method` (`POST`), `headers`. The body is the JSON event shown below. |
| `ntfy` | `url` (topic URL), `token` or `username`/`password`, `priority` (1-5, for down/reminder; default 4). |
| `gotify` | `url`, `token` (application token), `priority`. |
| `matrix` | `homeserver`, `room_id`, `access_token`. |
| `discord` | `webhook_url`. |
| `slack` | `webhook_url`. |
| `telegram` | `bot_token`, `chat_id`, `api_url`. |
| `pushover` | `user_key`, `app_token`, `priority`. |
| `email` | `host`, `port`, `security` (`starttls` default, `tls`, `none`), `username`, `password`, `from`, `to` (list). |

Webhook body:

```json
{
  "event": "down",
  "monitor_id": "website",
  "monitor_name": "example.com",
  "monitor_type": "http",
  "target": "https://example.com/",
  "group": "web",
  "tags": ["public"],
  "status": "down",
  "previous_status": "pending",
  "message": "HTTP 503 is not accepted",
  "timestamp": 1792540800000,
  "since": 1792540800000,
  "latency_ms": 41.2
}
```

Failed deliveries are retried after 5 s and 30 s. Test a notifier with
`POST /api/v1/notifiers/{id}/test`.

## `groups`

```yaml
groups:
  - id: network
    name: Network            # default: id
    description: …
    tags: [infra]            # inherited by members
    parent: infra            # optional, for nesting
    status_policy: any_down  # or all_down
    defaults:                # inherited by members (nearest group wins)
      interval: 30s
      notify: [oncall]
```

`defaults` takes `interval`, `timeout`, `failure_threshold`,
`recovery_threshold`, `notify`, `renotify_every`, `notify_degraded`, `flapping`
and `degraded_latency`.

A group's status is computed from its members, including subgroups:

- **Down:** with `any_down`, when any member is down; with `all_down`, when
  every member is down. Under `all_down`, some members down makes the group
  degraded.
- **Degraded:** when any member is degraded or pending.
- **Up:** otherwise.
- **Ignored:** paused, unknown and maintenance members.

## `monitors`

Keys common to every monitor:

| Key | Description |
|---|---|
| `id` | Required, stable. History is keyed by it. |
| `type` | `icmp`, `tcp`, `udp`, `http`, `tls`, `dns`, `ntp`, `postgres`, `mysql`, `push`. |
| `name`, `description` | Display only. |
| `group` | Group id. |
| `tags` | Own tags; group tags are added to them. |
| `enabled` | `false` keeps the monitor in the configuration without running it. |
| `interval`, `timeout`, `failure_threshold`, `recovery_threshold`, `notify`, `renotify_every`, `notify_degraded` | Override the group and global defaults. |
| `flapping` | `{window, max_transitions}`, or `false` to disable an inherited setting. |
| `degraded_latency` | Report `degraded` when a successful check takes longer than this. |
| `depends_on` | Monitor ids. While one of them is down, this monitor's down notifications are suppressed. |

The type-specific keys are documented in [checks.md](checks.md).

## `maintenance`

```yaml
maintenance:
  - id: nightly
    description: Backups
    # selection: any combination; at least one is required
    monitors: [nas]
    groups: [storage]
    tags: [backup]
    all: false
    # either a one-off window…
    start: 2026-11-14T08:00:00+01:00
    end: 2026-11-14T18:00:00+01:00
    # …or a weekly recurring one
    recurring:
      days: [mon, tue, wed, thu, fri]   # empty: every day
      start: "02:00"
      duration: 1h
      timezone: Europe/Oslo             # IANA name, default UTC
```

During a window, checks still run, results are recorded as `maintenance`, and
no notifications are sent. Uptime figures exclude maintenance time.

## Alerting behaviour

1. Every check yields `up`, `degraded` or `down`.
2. `degraded_latency` can turn an `up` into `degraded`.
3. Failures move a monitor to `pending`, and to `down` once
   `failure_threshold` is reached. Successes move it back after
   `recovery_threshold`.
4. A notification is sent when the status differs from the last *notified*
   status:
   - `down`: an outage.
   - `up`: recovery from a notified outage, or from degraded.
   - `degraded`.
   - `reminder`: every `renotify_every` while down.
   - `flapping`: once, when flap detection triggers.
5. Suppressions are recorded on the event (`suppressed_reason`):
   - A dependency is down. Applies to down notifications and reminders.
   - The monitor is flapping.
   - Maintenance.

   A suppressed outage that persists afterwards is notified then.
