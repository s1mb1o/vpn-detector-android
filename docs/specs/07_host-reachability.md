# HOST_REACHABILITY Parity Checks

Purpose: add a narrow compatibility layer for the `HOST_REACHABILITY`
anti-fraud telemetry pipeline documented in public RU research
(reference-messenger app, 2026-04), without letting that narrower logic
replace the richer detector already implemented here.

## Scope

Two checks are added in the `PROBES` category:

1. `ref_ip_first_success`
2. `ref_host_reachability`

They are parity-oriented diagnostics. They do not redefine the main scoring
model and they intentionally stay low-weight / unscored unless they expose a
real transport mismatch that the broader detector should already investigate.

## `ref_ip_first_success`

### Goal

Mirror the reference collector's IP-discovery semantics:

- exact endpoint set
- shuffled order
- low-level socket transport
- first successful non-loopback IP wins

### Endpoint set

- `https://ipv4-internet.yandex.net/api/v0/ip`
- `https://ipv6-internet.yandex.net/api/v0/ip`
- `https://ifconfig.me/ip`
- `https://api.ipify.org?format=json`
- `https://checkip.amazonaws.com/`
- `https://ip.mail.ru/`

### Transport

- `java.net.Socket` for plain HTTP
- `SSLSocket` for HTTPS
- manual HTTP `GET`, `Connection: close`
- no OkHttp

### Output

- winner endpoint + IP in the row value
- per-endpoint DetailEntry:
  - success
  - parse failure
  - transport error
  - skipped after winner
- one informational detail with the parallel GeoIP probe set, so QA can see
  whether the reference-style winner agrees with the richer collector

### Severity

- `INFO` when the winner IP is also present in the normal parallel probe set
- `SOFT` only when the winner IP is absent from the parallel set, because that
  suggests path-dependent behavior worth investigating

## `ref_host_reachability`

### Goal

Mirror the exact five hosts documented in the reference pipeline, recorded
as booleans.

### Host set

- `api.oneme.ru`
- `gstatic.com`
- `mtalk.google.com`
- `calls.okcdn.ru`
- `gosuslugi.ru`

### Port policy

- default HTTPS-style services: `tcp/443`
- `mtalk.google.com`: Google push ports `5228`, `5229`, `5230`

### Transport

- raw TCP connect only
- no HTTP semantics required
- host is considered reachable when any configured port accepts a connection

### Output

- aggregate value: reachable count + missing hosts
- per-host DetailEntry with the successful port or the last transport error

### Severity

- row severity is always `INFO`
- per-host details use `PASS` for reachable and `SOFT` for unreachable

Reason: the reference pipeline itself uses this as a network-environment
fingerprint in combination with VPN flag, operator, connection type, and
account context. The boolean pattern is useful for parity and diagnosis, but
too ambiguous to score as a standalone anti-VPN signal.

## Non-goals

- replaying the reference telemetry upload format to a backend
- guaranteed-delivery queueing
- foreground auto-run or PMS-style remote enable flags
- reproducing the in-call VPN-warning UI

Those are upstream behavior details, but not additional VPN detection methods.
