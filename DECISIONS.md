# Design decisions

Decisions taken while building Pingwarden, with their rationale. Each can be
revisited; the "Revisit when" notes say what would change the answer.

## Scope and architecture

### D1. Single binary, headless, API-first
Pingwarden is one process: scheduler, checks, alerting, persistence and an
HTTP API (`/api/v1`, `/metrics`, `/healthz`, `/readyz`). UIs (TypeScript,
later) and the status page (separate project) are API clients. The
configuration is read-only code, so the API is read-mostly. Its only writes
are runtime actions: pause/resume, run now, reload, test a notifier, push,
and (D33, D34) acknowledge, silence and short maintenance windows.

### D2. Configuration as code, state in SQL
YAML files define everything that is configuration: monitors, groups,
notifiers, maintenance windows. The database stores only state and history:
monitor state, heartbeats, rollups, events, the notification log. The database
never stores monitor configuration, so it holds no secrets. It keeps only id,
name, type, a credential-free target and the description. Runtime maintenance
windows (D34) are the one exception, deliberately bounded.

### D3. PostgreSQL and MariaDB only (no SQLite)
As requested. Both are reached through sqlx's `Any` driver:

- **One SQL text for both engines.** Queries are written once with `?`
  placeholders, which are rewritten to `$n` for PostgreSQL.
- **Per-dialect SQL only where syntax differs:** upserts
  (`ON CONFLICT` / `ON DUPLICATE KEY UPDATE`), chunked deletes (MariaDB
  `DELETE … LIMIT`), advisory locks.
- **Portable column types.** Timestamps are `BIGINT` milliseconds since the
  epoch and booleans are `SMALLINT`, because `Any` supports few types and the
  two engines disagree on dates and booleans.
- **Two migration trees.** `migrations/postgres` and `migrations/mysql` are
  kept in sync by hand.
- **MariaDB syntax.** `VALUES()` is used in upserts. It is deprecated in
  MySQL 8.0.20+ but is the MariaDB syntax. MySQL itself is not a target,
  though `mysql://` URLs work.

*Revisit when* a third engine is wanted, or the per-dialect SQL grows enough
that typed per-engine stores (`PgPool` / `MySqlPool`) become the simpler option.

### D4. Leader election through a database advisory lock
Several instances can share one database. Only the holder of a session-scoped
advisory lock runs checks: `pg_try_advisory_lock` on PostgreSQL, `GET_LOCK` on
MariaDB. The others stand by and retry every 10 s. The leader re-checks its
lock connection every 5 s and stops all checks when it is lost. Tested: a
standby takes over within about 10 s of the leader stopping.

The live API endpoints answer 503 on a standby. `/readyz` reports ready once
the database is reachable, whatever the role; `/readyz?role=leader` adds the
leader condition. For Kubernetes the example uses one replica with the
`Recreate` strategy, because a standby that is never "ready" would block a
rolling update.

*Revisit when* real HA with an always-ready API is wanted. Standbys would then
serve reads from the database instead of returning 503.

### D5. Groups (categories) and tags
- **Groups are the "categories".** They are declared in `groups:`, nest
  through `parent:`, and carry `tags` and `defaults`.
- **Membership.** A monitor joins one group with `group:`. It belongs to one
  group only, so settings inheritance stays unambiguous.
- **Tags** are free-form strings on monitors and groups, such as `prod` or
  `team:infra`.
- **Effective tags.** A monitor's effective tags are its own tags plus those of
  its group chain. The API, `/metrics`, notifications and maintenance windows
  (`tags:`) all use the effective tags.
- **Inheritance.** Settings resolve nearest-first: the monitor's own value,
  then its group, then each parent group, then global `defaults`.
- **Group status** is computed live from the members, including members of
  subgroups:
  - `status_policy: any_down` (the default): down when any member is down.
  - `all_down`: down only when every member is down, which suits redundant
    uplinks or replicas.
  - Degraded when any member is degraded or pending.
  - Paused, unknown and maintenance members are ignored.
- **Groups do not notify** in v1. Monitors notify, and `depends_on` suppresses
  downstream noise.

*Revisit when* group-level notifications are wanted. They can be built on the
same state machine, fed with the aggregated status.

### D6. Monitor identity is the configured `id`
Every monitor needs a stable `id` (letters, digits, `_-.`, at most 128
characters). The `id` keys all history, so renaming the display `name` is free.
A monitor that disappears from the configuration is flagged `removed_at`. Its
history is purged after `retention.removed_monitors` (30 days by default), so
an accidental removal followed by a revert loses nothing.

## Alerting semantics

### D7. Hysteresis with a pending state
A monitor goes `down` after `failure_threshold` consecutive failures (3 by
default) and shows `pending` before that. It recovers after
`recovery_threshold` consecutive successes (1 by default). Heartbeats store
the *raw* outcome, so uptime figures count pending failures as down. That is
deliberate: the service *was* failing.

### D8. Notify on the difference from the last notified status
Notifications compare the current status with the last *notified* status,
not only with the previous status. As a result:

- A recovery is sent only for an outage that was notified.
- A notification suppressed by a down dependency, or by flapping, is sent
  later if the condition still holds once the suppression ends.
- The first result ever notifies only when it is down.
- The notified status is persisted, so restarts neither re-notify nor forget
  an outage.

### D9. Dependencies suppress down notifications only
When a monitor in `depends_on` is down, down notifications and reminders are
suppressed. The event is still recorded, with
`suppressed_reason = "dependency X is down"`. The status itself is still
computed honestly.

### D10. Flap detection is opt-in
`flapping: {window, max_transitions}` counts up↔down flips. When the limit is
exceeded, one `flapping` notification is sent and further notifications are
suppressed until the count falls to half the limit. It is off by default
because a fresh setup should not hide alerts.

### D11. Maintenance: checks still run
During a maintenance window, checks keep running and record `maintenance`
heartbeats, and no notifications are sent. Uptime calculations exclude
maintenance. One-off windows take RFC 3339 timestamps. Recurring windows are
weekly, by day and local time in an IANA timezone; DST is handled by jiff.
Recurring windows are limited to 7 days. Selection is by `monitors`, `groups`,
`tags`, or `all: true`; an empty selection is rejected, not taken as "all".

## Checks

### D12. ICMP: datagram sockets first, raw sockets second
surge-ping opens a datagram ICMP socket first, then a raw one. Tested on
rootless Docker 29 with the image's non-root user (65532):

| Setup | ICMP |
|---|---|
| `--cap-drop ALL` | fails (rootless Docker sets no `ping_group_range`) |
| `--cap-drop ALL --cap-add NET_RAW` as user 65532 | **fails** |
| `--cap-drop ALL --cap-add NET_RAW --user 0` | works |
| `--cap-drop ALL --sysctl net.ipv4.ping_group_range="65532 65532"` | **works, no capability** |

The `--user 65532` + `NET_RAW` case fails because Docker does not give
non-root users ambient capabilities. Added capabilities only reach the bounding
set, and `no-new-privileges` blocks file capabilities too. The recommended
setup is therefore the sysctl, which is also a "safe" sysctl in Kubernetes.
`CAP_NET_RAW` remains supported for anyone who runs the container as root.
Rootless Docker rejects `0 2147483647` because the user namespace does not map
that whole range.

### D13. Name resolution through hickory, IPv4 preferred for `ip_version: any`
- **Resolver.** hickory-resolver reads `/etc/resolv.conf` and `/etc/hosts`.
  The alternative, getaddrinfo, blocks a thread per lookup and behaves
  inconsistently on musl.
- **IPv4 first.** With `ip_version: any` an IPv4 address is used when there is
  one. Many container networks have no IPv6 route; the e2e test hit exactly
  that. Use `ip_version: 6` to monitor IPv6.
- **DNS checks get their own resolver,** uncached and with one attempt, so
  every check reaches the server.

### D14. Certificate checks never abort the handshake
A custom rustls verifier records the chain and the verification error, then
lets the handshake finish. The check can therefore report precisely: expired
(with date), self-signed or unknown issuer, wrong host name, not yet valid.
Expiry is the earliest `notAfter` of the presented chain, so an expiring
intermediate is caught too. Hostname and chain verification can be switched
off separately. Supported STARTTLS protocols: SMTP, IMAP, POP3, FTP,
PostgreSQL, LDAP. XMPP and MySQL are not supported: they need stream or
handshake parsing beyond a few lines.

### D15. UDP semantics are explicit
- **A reply proves the service is up.** With `expect`/`expect_hex`/
  `expect_regex` it must also match.
- **ICMP port-unreachable proves it is down.** It arrives as `ECONNREFUSED` on
  the connected socket.
- **Silence is down by default.** With `expect_response: false` it counts as
  up, for services that never answer, such as WireGuard. In that mode only an
  ICMP error can mark the service down; the documentation says this is weak.

### D16. HTTP checks open a fresh connection every time
The client keeps no idle connections (`pool_max_idle_per_host(0)`). Every
check then measures the real connect and TLS handshake, and no idle sockets sit
in memory. Latency is time to the end of the read body; the body is read only
when keyword or JSON matching needs it, capped at `max_body_size`.

### D17. Push monitors
Push monitors use `GET` or `POST /api/v1/push/{token}?status=up|down|degraded&msg=…&ping=…`.
The token is the only credential: at least 16 characters of `[A-Za-z0-9_-]`,
unique. The monitor goes down when no push arrives within `interval`. Unknown
and disabled tokens both return 404.

## Notifications

### D18. Built-in providers, no templating engine
The built-in providers are webhook (JSON body = the event), ntfy, Gotify,
Matrix, Discord, Slack, Telegram, Pushover and email (SMTP with STARTTLS,
implicit TLS or plain). Messages have a fixed format. A templating engine would
add weight; the webhook covers custom formatting downstream.

- **Delivery** runs in a background task, at most 8 at a time.
- **Retries:** after 5 s, then after 30 s.
- **Logging:** each delivery is recorded in the `notifications` table and in
  `/metrics`.
- **Filtering:** a notifier can be limited to some events (`events: [down, up]`).

*Revisit when* custom message templates are requested.

## Persistence

### D19. Batched writer, aggregated rollups, chunked retention
- **No waiting on the database.** Monitors enqueue writes. A single writer
  task flushes every second, or as soon as 500 heartbeats are pending.
- **Database outages.** Operations are kept and retried with backoff. Beyond
  50,000 pending heartbeats the oldest are dropped, which `/metrics` counts.
- **Rollups.** Hourly and daily rollups (counts, latency sum/count/min/max)
  are updated additively in the same transaction as the heartbeats. Uptime
  queries never scan raw heartbeats.
- **Default retention:** raw heartbeats 14 days, hourly rollups 400 days,
  daily rollups forever, events 400 days, notification log 90 days.
- **Deletes** run in batches of 5,000 rows, so locks stay short.

## Runtime and footprint

### D20. Memory first
- **Measured:** 4.7 MiB RSS (5.7 MiB before static linking) with 15 monitors of every type (`docker stats`
  after one minute).
- **Runtime.** Tokio uses 2 worker threads by default; `runtime.worker_threads: 1`
  selects the single-threaded runtime. Thread stacks are 512 KiB and there are
  at most 4 blocking threads.
- **Concurrency.** At most 64 checks run at once (`runtime.max_concurrent_checks`).
- **Allocator.** The default is the system (musl) allocator, which has the
  smallest footprint. The opt-in `mimalloc` cargo feature trades memory for
  speed.
- **Release profile:** `opt-level = "s"`, fat LTO, one codegen unit, stripped.
  The binary is about 10 MB.
- **Dependencies** are added with `default-features = false`. aws-lc-rs and
  OpenSSL are banned in `deny.toml`.

### D21. rustls with ring
ring is the crypto provider everywhere: checks, HTTP client, SMTP, sqlx. It is
installed as the process default at startup. aws-lc-rs would need cmake and
perl, which the DHI build image does not ship. System trust roots come from
the runtime image's `/etc/ssl/certs/ca-certificates.crt`; extra CAs come from `tls.ca_files` or a
monitor's `ca_file`.

### D22. YAML: serde-saphyr with YAML 1.2 booleans
serde_yaml is unmaintained, so the parser is serde-saphyr. `strict_booleans` is
on, so `no`, `on` and `y` stay strings (the "Norway problem"). The e2e tests
found an `id: y` turned into `true`.

- **`${…}` substitution** runs on parsed string values, never on raw text, so
  a secret containing YAML syntax cannot change the document. Forms:
  `${VAR}`, `${VAR:-default}`, `${file:/path}` for Docker and Kubernetes
  secrets, and `$$` for a literal `$`.
- **Typed values.** A value that is exactly one reference may become a number
  or a boolean, so `port: ${PORT}` works. If the field wants a string (a
  numeric password, say), the original text is restored.
- **Strict schema.** Unknown keys are errors, reported with their path.
  Validation collects every error, so one run lists them all.
- **Configuration directories.** The configuration path may be a directory:
  `*.yaml` and `*.yml` are loaded in name order and merged; hidden files, such
  as Kubernetes `..data`, are skipped. Sections (`server`, `database`, …) may
  appear in one file only.
- **Reload** with `SIGHUP` or `POST /api/v1/reload`. An invalid configuration
  is rejected and the running one kept. Only changed monitors restart, and they
  keep their state. Changes to `server`, `database`, `tls` and `runtime` are
  logged as needing a restart.

## Build, image and CI

### D23. Docker Hardened Images, pinned by index digest, static binary
- **Build image:** `dhi.io/rust:1-alpine3.24-dev`. **Runtime image:**
  `dhi.io/alpine-base:3.24`, about 3 MB with a CA bundle and the non-root user
  65532.
- **Index digests.** The Dockerfile pins multi-arch **index** digests, so
  arm64 builds work and Renovate can update them. The digests in the brief
  were amd64-only manifests.
- **Syntax directive.** `# syntax=docker/dockerfile:1.28.0` is pinned by
  digest too.
- **Static linking.** The binary is linked fully statically
  (`-C target-feature=+crt-static`, built with an explicit `--target` so
  proc-macros stay dynamic). It needs nothing from the runtime image: neither
  musl nor `libgcc_s`, which `alpine-base` lacks.
- **Runtime base change.** The brief's `dhi.io/rust:1-alpine3.24` runtime
  image was replaced, because it ships the whole toolchain (216 MB). The image
  is now **8.2 MB**. The full container end-to-end run gives identical results,
  at 4.7 MiB RSS.
- **Rust 1.96.** The DHI image ships Rust 1.96 from Alpine. That is the MSRV
  (`rust-version`) and the CI toolchain, so local, CI and image builds agree.
  The image has no clippy, rustfmt or rustdoc, so CI lints use rustup, and
  doctests are disabled since there are none.
- **Container user:** 65532, read-only root filesystem, the `healthcheck`
  subcommand for `HEALTHCHECK`. Time zones are compiled in; the base image has
  no zoneinfo.

*Revisit when* a shell-less image is wanted: the static binary also runs on a
`scratch`-like base, given a CA bundle.

### D24. CI
- **ci.yaml:** rustfmt, clippy `-D warnings`, tests against the latest PostgreSQL and
  MariaDB service containers, the example configuration validated,
  yamllint, cargo-deny (advisories, bans, licenses, sources), and a Docker
  build with a smoke test.
- **release.yaml:** multi-arch images (amd64 and arm64 on native runners,
  merged by digest) pushed to `ghcr.io/sebastka/pingwarden` with SBOM and
  provenance. Pushes to `master` publish `edge`; `v*` tags publish semver tags.
- **Pinning:** Actions are pinned by commit SHA, with the version in a comment.
- **Updates:** Renovate; see D27.
- **Credentials:** pulling DHI images uses the `DOCKERHUB_USERNAME` variable and the `DOCKERHUB_TOKEN` secret.
  Pull requests from forks skip the Docker job.

### D25. License: MIT
I chose this to match Uptime Kuma. Change `Cargo.toml` and `LICENSE` if you
prefer something else.

### D26. Endpoint groups on configurable listeners
- **Groups.** HTTP endpoints form four groups: `health` (`/healthz`,
  `/readyz`), `metrics`, `api` (`/api/v1` except push) and `push`.
- **Listeners.** `server.listeners` binds any number of addresses, each
  serving a chosen set of groups. The consumer can then expose push publicly,
  keep the API internal and scrape metrics on a separate port, without
  path-based filtering at a proxy. `server.listen` remains as shorthand for
  one listener serving everything (the default, `0.0.0.0:8080`).
- **Fail fast.** All listeners are bound before any serves, so a bad address
  stops the start.
- **Healthcheck.** `pingwarden healthcheck` reads the configuration to find
  the `health` listener, so the image's `HEALTHCHECK` works with any layout.
- **No TLS.** Pingwarden serves plain HTTP; TLS termination belongs to the
  proxy or ingress.

### D27. Renovate rather than Dependabot
Dependabot's parsers read only `FROM` lines in Dockerfiles and `uses:` in
workflows (checked in dependabot-core). It would therefore miss:
- the pinned `# syntax=` directive;
- the PostgreSQL and MariaDB service containers in CI;
- the yamllint version run through pipx.

Renovate (`renovate.json5`, hosted Mend app) covers all of them:
- **Schedule:** it runs nightly (00:00-06:00 Europe/Paris), and grouped PRs
  merge themselves through GitHub auto-merge once the required checks pass.
  GitHub signs the squash commits, so they satisfy the signed-commit rule.
- **Majors are reviewed by hand,** and so are Cargo `0.x` minor bumps, which
  are semver-incompatible in Cargo. Exception: the PostgreSQL and MariaDB
  service containers of CI track the latest releases, majors included
  (pinned to `major.minor`, e.g. `mariadb:13.0`, so every bump is a tested
  PR). The PostgreSQL image of the compose example stays manual, because a
  major upgrade there needs a data migration.
- **Release age:** releases wait 3 days before being proposed, except
  security fixes.
- **Cargo:** requirements in `Cargo.toml` are raised (`rangeStrategy: bump`),
  and lock file maintenance refreshes transitive dependencies.
- **Registry access:** credentials live in Mend, not in the repository.
  User-scope host rules in the Mend developer portal cover `dhi.io`,
  `docker.io` and `hub.docker.com` (type `docker`, Docker Hub username, the
  `DOCKERHUB_TOKEN` secret as password). Mend did not pass a user-scope
  *variable* to runs, so `{{ variables.… }}` in `renovate.json5` failed
  validation.
- **Security alerts:** Dependabot alerts stay enabled as Renovate's
  vulnerability source. Dependabot security-update PRs are disabled to avoid
  duplicates.
- **Toolchain:** CI installs Rust with rustup instead of the branch-pinned
  `dtolnay/rust-toolchain` action, which neither bot can update. The toolchain
  version (`RUST_TOOLCHAIN`, `rust-version`) deliberately stays manual: it
  follows the Rust shipped in the DHI build image, so it is bumped when a base
  image update brings a new Rust.

### D28. OpenID Connect access tokens, validated locally
- **Resource server only.** Pingwarden accepts JWT access tokens from an
  existing provider and never issues tokens: running an authorization server
  (clients, users, login pages, key rotation) does not belong in a headless
  monitor. Browser UIs sign users in with the provider (authorization code
  with PKCE); machines use client credentials at the provider.
- **Static tokens stay.** Push tokens, the metrics token and `api_tokens`
  serve cron jobs, Prometheus and scripts, which cannot run OAuth flows
  easily. Both kinds of token are accepted side by side.
- **Local validation with `ring`.** Signatures are verified with ring, which
  rustls already uses, against keys discovered from the issuer (JWKS),
  cached and refreshed hourly or on an unknown key id (rate-limited to once
  per 30 s). `jsonwebtoken` was avoided: its pure-Rust backend depends on
  the `rsa` crate, which has an open advisory (timing side channel) that
  cargo-deny would flag. No session state, no introspection round-trip.
- **Strict checks.** Asymmetric algorithms only (never `none` or HMAC); the
  key's declared algorithm must match the header; `exp` is required;
  `iss`, `aud` and `nbf` are checked with a configurable leeway. A
  configured audience is mandatory, so tokens minted for other applications
  of the same realm are refused.
- **Permissions** map a claim (`scope`, `groups`, `realm_access.roles`, …)
  to the existing `read` and `admin` levels. Admin actions are logged with
  the caller's identity.
- **CORS** (`server.cors`) is built in, since browser UIs on another origin
  need it whatever the token type. Preflight requests are answered before
  authentication; only bearer tokens are used, never cookies.
- **Tested** against a mock provider (integration test) and a real
  Keycloak 26 with the client-credentials grant and RS256 keys.

### D29. "Who am I": `GET /api/v1/me`
- **Choice.** A read endpoint returns the caller's name (as in audit logs,
  without its prefix), the kind of credential (`token`, `oidc`,
  `anonymous`) and its scope (`read` or `admin`).
- **Why.** A UI must know whether to offer actions. Without this it has to
  mirror the OIDC role mapping in its own configuration, or learn from a
  first refused action. Pingwarden already resolved the scope for the
  request; returning it costs nothing and keeps one source of truth.

### D30. Rollups of every monitor in one request
- **Choice.** `GET /api/v1/rollups?resolution=&from=&to=&tag=&group=`
  returns `{monitor id: [rollups]}` for every configured monitor matching
  the filters (`[]` without data), from **one** SQL query on the
  `(resolution, bucket)` index. Ranges are capped: 31 days of hourly or
  400 days of daily rollups.
- **Why.** A dashboard showing a 24-hour bar per monitor otherwise sends one
  request per monitor per refresh. The cap bounds the answer's size
  (memory first, D20): 200 monitors × 744 hours is about 150k small rows.
- **Not by monitor list.** Filters are the existing tag and group ones;
  arbitrary id lists would make long URLs for little gain.

*Revisit when* installations with thousands of monitors need paging.

### D31. Live changes as server-sent events
- **Choice.** `GET /api/v1/stream` (read scope) streams changes as SSE:
  `transition` and `notification` (the same JSON as the list endpoints,
  with ids), `monitor` (`{id}`: live state changed without a transition),
  `maintenance`, `reload`, and `resync`. A `: keepalive` comment every 15 s
  keeps proxies from closing idle streams.
- **Broadcast channel.** The engine publishes into a `tokio::sync::broadcast`
  channel of 256 changes; each stream holds a receiver. A receiver that
  falls behind loses the oldest changes and receives `resync`, so one slow
  client never holds memory for the others nor slows the engine.
- **Ids come from the database.** Transitions and deliveries are published
  by the writer once stored (`RETURNING id` on PostgreSQL, the last insert
  id on MariaDB), so a client can de-duplicate against what it listed. They
  arrive up to a second late (the writer's batch interval), and not at all
  while the database is down (they are published when stored).
- **Bounded.** At most 64 concurrent streams (503 beyond). A stream ends
  when the engine stops (shutdown, lost leadership); clients reconnect, as
  `EventSource` does. Standbys answer 503, like the other live endpoints.
- **SSE, not WebSocket.** One direction is enough; SSE is plain HTTP that
  passes proxies and CORS like other GETs, and axum supports it with one
  small dependency (`futures-util`, already in the tree, for the stream).
- **Not every check.** Heartbeats are not streamed: with many monitors they
  would dominate the traffic, and UIs refetch the list on a change anyway.

### D32. Uptime targets (`slo`) are exposed, not computed
- **Choice.** `slo` (a percentage strictly between 0 and 100) is accepted in
  `defaults`, group `defaults` and on monitors, inherited like the other
  settings, and returned on monitors and in their effective configuration.
  Pingwarden computes nothing with it.
- **Why.** Error budgets are a presentation concern: a UI combines the
  target with uptime data it already reads. Keeping the target in the
  configuration keeps it versioned with the monitors.

*Revisit when* budget alerts are wanted ("80 % of the month's budget
used"), which would need the computation here.

### D33. Acknowledge and silence
- **Acknowledge** (`POST …/ack`, optional comment; `…/unack`): allowed when
  the monitor is down, pending or degraded (409 otherwise, so nobody
  acknowledges a healthy monitor by mistake). It stops **reminders** only:
  recoveries and new outages are still notified. It is cleared when the
  monitor is up again, so the next outage notifies normally.
- **Silence** (`POST …/silence` with `duration` or `until`, at most 7 days;
  `…/unsilence`): **every** notification about the monitor is suppressed,
  including flapping. Transitions record
  `suppressed_reason = "silenced by <who> until <time>"`. When it ends, the
  usual rule applies (D8): a status that still differs from the last
  notified one is notified then. A silence that ran out is shown as none,
  even before the next check clears it.
- **State, not configuration.** Both are part of the monitor's persisted
  state (new nullable columns of `monitor_state`), applied by the monitor's
  own task like pause, so they survive restarts and leader changes, and a
  configuration reload keeps them. Each change is audited with the caller
  and published on the stream (`monitor`).
- **Why both.** Acknowledging says "someone is on it" for the current
  problem; silencing covers planned noise on one monitor without a
  maintenance window (which would also change its status and uptime).

### D34. Runtime maintenance windows ⚠️ configuration as code
- **Choice.** `POST /api/v1/maintenance` creates a one-off window (a
  selection as in the configuration, `start` defaulting to now, `end` or
  `duration`); `POST /api/v1/maintenance/{id}/end` ends one early. They are
  stored in a new `maintenance_windows` table, loaded at start, and apply
  exactly like one-off configured windows.
- **The tension.** D2 keeps configuration in YAML. This is acceptable
  because runtime windows are **ephemeral and bounded**: one-off only, at
  most 30 days long and starting at most 30 days ahead, purged a week
  after they end; **audited** (`created_by`, logged); and **separate**:
  configured windows cannot be ended or changed through the API (409), ids
  cannot collide with them, and the listing says `source: config|api`.
  Anything recurring or lasting belongs in the configuration.
- **Why.** "Put the router in maintenance for an hour" is an operational
  act during an incident; a commit, review and reload for it is the wrong
  tool and invites forgetting to remove the window.
- **Applying.** The engine merges runtime windows with configured ones;
  monitors see a window at their next check. A 5-second loop publishes
  `maintenance` on the stream when the set of active windows changes, also
  for windows that start or end by themselves.

*Revisit when* runtime recurring windows are asked for: at that point the
configuration should probably move to the database as a whole, or not.

### D35. Effective configuration by allow-list
- **Choice.** `GET /api/v1/monitors/{id}/config` returns the resolved
  settings (inheritance applied: interval, timeout, thresholds, flapping,
  `slo`, notifiers, dependencies…) and the check's options, built field by
  field from an **allow-list** per check type.
- **Never a secret.** Passwords, tokens, push tokens, header *values*,
  request bodies and TCP/UDP payloads (which may carry credentials) are
  left out; only header names and "sends a body/payload" flags remain. URLs
  go through the same redaction as `target` (no user info, query or
  fragment), database URLs included. A unit test feeds secrets into every
  field and checks none comes out.
- **Why an allow-list.** A deny-list would leak the next secret field added
  to a check; an allow-list at worst omits a harmless one.

### D36. `cert_expires_at`
TLS monitors expose `cert_expires_at` in milliseconds, like every other
timestamp of the API. `cert_expiry` (seconds) stays, marked deprecated in
the OpenAPI spec, so existing clients keep working.

### D37. Webhooks with GET or HEAD send no body
A webhook notifier with `method: GET` (or `HEAD`) used to send the JSON
event as a body anyway. A GET with a body is undefined in HTTP semantics;
some servers reject it, and one tested server hung on it until the
notification timed out. Such webhooks now send no body; use POST (the
default) to receive the event.

## Not done yet

- **Stored OpenAPI spec.** `docs/openapi.yaml` is hand-written; generating it
  from code (e.g. utoipa) would keep it in sync, at a compile-time cost.
- **Configuration file watching.** Reloading currently needs `SIGHUP` or the
  API.
- **More checks:** gRPC health, WebSocket, SNMP, RADIUS, Docker container
  state, and SSH beyond banner matching.
- **Group-level notifications** and custom message templates.
