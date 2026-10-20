# Checks

Every check runs within the monitor's `timeout`. Host names are resolved
through `/etc/resolv.conf` and `/etc/hosts`. Where `ip_version` exists it is
`any` (the default, preferring IPv4), `4` or `6`.

Latency is the connect or round-trip time, as described per check. It is
exported on `/metrics` and used by `degraded_latency`.

## `icmp` (alias `ping`)

| Key | Default | Description |
|---|---|---|
| `host` | required | Name or address. |
| `count` | `3` | Echo requests, sent 200 ms apart. |
| `packet_size` | `56` | Payload bytes. |
| `packet_timeout` | `1s` | Wait per reply. |
| `down_loss_percent` | `100` | Down at or above this loss. |
| `degraded_loss_percent` | unset | Degraded at or above this loss. |
| `ip_version` | `any` | |

Latency is the average round trip. ICMP needs either a `ping_group_range`
covering the process's GID, or `CAP_NET_RAW`; see
[deployment.md](deployment.md#icmp). If neither is available, ICMP monitors
report the reason and every other check keeps working.

## `tcp`

| Key | Default | Description |
|---|---|---|
| `host`, `port` | required | |
| `tls` | `false` | Handshake TLS after connecting. |
| `tls_verify` | `true` | Verify the certificate when `tls` is set. |
| `sni` | `host` | Server name for TLS. |
| `send` / `send_hex` | unset | Bytes to send. `send` understands `\r \n \t \0 \\ \xHH`. |
| `expect` | unset | Substring expected in the reply (same escapes). |
| `expect_regex` | unset | Regular expression the reply must match. |
| `ip_version` | `any` | |

Up when the connection (and the optional exchange) succeeds. Reading stops
after 8 KiB. Latency is the TCP connect time. Banner checks work this way:
`expect: "SSH-"`, `expect: "220 "` (SMTP/FTP), `expect: "+OK"` (POP3).

## `udp`

| Key | Default | Description |
|---|---|---|
| `host`, `port` | required | |
| `payload` / `payload_hex` | empty | Datagram to send. |
| `expect` / `expect_hex` / `expect_regex` | unset | Required content of the reply. |
| `expect_response` | `true` | Whether silence means down. |
| `ip_version` | `any` | |

UDP has no handshake, so only two things prove anything:

- A **reply** proves the service is up. With an `expect*` key the reply must
  also match.
- An **ICMP port-unreachable** proves it is down. It is reported as "port
  unreachable".

**Silence** proves nothing. With `expect_response: true`, silence until the
timeout is down. With `expect_response: false`, silence after 2 s is up
("open or filtered"). That suits services that never answer unauthenticated
packets, such as WireGuard. Be aware that a firewall dropping the traffic also
looks up in that mode.

Prefer protocol-aware probes, such as a DNS query (see the example
configuration), or the `dns` and `ntp` checks.

## `http`

| Key | Default | Description |
|---|---|---|
| `url` | required | `http` or `https`. |
| `method` | `GET` | |
| `headers` | `{}` | |
| `body` | unset | Request body. |
| `accepted_status` | `["200-299"]` | Codes, ranges (`200-299`) or classes (`2xx`). |
| `keyword` / `keyword_regex` | unset | Must appear in the body. |
| `invert_keyword` | `false` | The keyword must *not* appear. |
| `json_path` / `json_value` | unset | Dotted path into a JSON body (`checks.0.status`); with `json_value`, the value must match. `1` matches `"1"`. |
| `follow_redirects` / `max_redirects` | `true` / `10` | |
| `tls_verify` | `true` | |
| `basic_auth` | unset | `{username, password}`. |
| `bearer_token` | unset | |
| `max_body_size` | `1048576` | Bytes read for keyword and JSON matching. |
| `ip_version` | `any` | |

Every check opens a fresh connection. Latency is time to the response, or to
the end of the body when it is read. For certificate expiry, add a `tls`
monitor.

## `tls` (alias `certificate`)

| Key | Default | Description |
|---|---|---|
| `host` | required | |
| `port` | `443` | |
| `sni` | `host` | Name sent and verified. |
| `starttls` | `none` | `smtp`, `imap`, `pop3`, `ftp`, `postgres` or `ldap`. |
| `verify_chain` | `true` | Down when the chain is not trusted. |
| `verify_hostname` | `true` | Down when the certificate does not match the name. |
| `expiry_warning` | `14d` | Degraded within this delay of expiry. |
| `expiry_down` | `0` | Down within this delay (`0`: once expired). |
| `ca_file` | unset | Extra PEM CA bundle for this monitor. |
| `ip_version` | `any` | |

The handshake always completes, so the message is precise: expiry date and
remaining days, issuer, untrusted or self-signed, name mismatch, not yet
valid. Expiry is the earliest `notAfter` of the presented chain, so an
expiring intermediate is reported too. Pingwarden exports it as
`pingwarden_monitor_cert_expiry_timestamp_seconds`. Latency is connect plus
handshake.

## `dns`

| Key | Default | Description |
|---|---|---|
| `domain` | required | Name to query. |
| `record_type` | `A` | `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `PTR`, `CAA`, … |
| `server` | system resolvers | `ip` or `ip:port`. |
| `protocol` | `udp` | `udp` or `tcp`. |
| `expect` | `[]` | Expected records, compared case-insensitively without trailing dots or quotes. MX is `"10 mail.example.com"`. |
| `expect_mode` | `contains` | `contains`: every expected record is present. `exact`: the answer is exactly the expected set. |

Queries are never answered from a cache. A check with no answer at all is down.

## `ntp`

| Key | Default | Description |
|---|---|---|
| `host` | required | |
| `port` | `123` | |
| `max_offset` | `1s` | Degraded when the absolute offset is larger. |
| `max_offset_down` | unset | Down when the absolute offset is larger. |
| `max_stratum` | `15` | Degraded when the server's stratum is higher. |
| `ip_version` | `any` | |

An SNTP v4 query. The check verifies that the reply echoes the request's
timestamp. A kiss-o'-death reply (stratum 0) or an unsynchronised server
(leap indicator 3) is down. Latency is the round trip.

## `postgres` and `mysql` (alias `mariadb`)

| Key | Default | Description |
|---|---|---|
| `url` | required | `postgres://…` or `mysql://`/`mariadb://…`, with TLS options in the URL. |
| `query` | `SELECT 1` | Executed after connecting. |

Up when the connection and the query succeed. Latency covers both.

## `push`

| Key | Description |
|---|---|
| `token` | Secret: at least 16 characters of letters, digits, `-` and `_`. |

The monitored job calls `GET` or `POST /api/v1/push/{token}`, optionally with
`?status=up|down|degraded&msg=text&ping=milliseconds`. No API token is needed;
the push token is the credential. The monitor goes down when no push arrives
within `interval`. Use a `failure_threshold` of 1 for jobs that push rarely.

```sh
curl -fsS "https://pingwarden.example.com/api/v1/push/$TOKEN?msg=backup+ok"
```
