# Proposed checks — bypass-direction signals

The current catalog (`01_signal-catalog.md`) detects whether the device *looks* like it's running a VPN. It does not directly probe whether the device is actually **bypassing the RU operator filtering policy**, which is a stronger and more useful signal for the QA harness. This doc proposes three new checks that close that gap.

Status: **specification only**. Implementation deferred until thresholds are validated against a real RU connection.

## Check A — `blocked_domain_reach`

| Property | Value |
|---|---|
| Category | `PROBES` |
| Inputs | small fixed list of long-blocked-in-RU foreign domains |
| Method | OkHttp `HEAD https://<domain>/`, 4 s timeout, no body |
| Severity rule | HARD if all reachable AND IP country = RU; SOFT if 1-of-N reachable; PASS if 0-of-N |
| Per-source details | one row per domain, classified `reachable` / `tls-rst` / `connect-timeout` / `nxdomain` |
| Files to touch | new `detect/probes/BlockedReachProbe.kt`, register in `DetectorEngine` |

**Domain shortlist (audited, all in RKN registry for ≥4 years):**
- `linkedin.com` — blocked since 2016
- `facebook.com` — blocked since 2022
- `instagram.com` — blocked since 2022

These are deliberately uncontroversial and stable. Do not include domains that are only throttled, regionally blocked, or politically sensitive.

**Code shape:**
```kotlin
suspend fun probe(host: String): BlockedDomainResult = withContext(Dispatchers.IO) {
    val req = Request.Builder().url("https://$host/").head().build()
    try {
        Http.client.newCall(req).execute().use { resp ->
            BlockedDomainResult(host, code = resp.code, kind = if (resp.isSuccessful || resp.code == 405)
                Kind.REACHABLE else Kind.HTTP_ERROR)
        }
    } catch (e: javax.net.ssl.SSLException)        { BlockedDomainResult(host, kind = Kind.TLS_RST,         err = e.message) }
    catch (e: java.net.SocketTimeoutException)     { BlockedDomainResult(host, kind = Kind.CONNECT_TIMEOUT, err = e.message) }
    catch (e: java.net.UnknownHostException)       { BlockedDomainResult(host, kind = Kind.NXDOMAIN,        err = e.message) }
    catch (e: Exception)                           { BlockedDomainResult(host, kind = Kind.OTHER,           err = e.message) }
}
```

The TLS handshake is done by OkHttp's normal stack, no custom certificate handling. We do not actually request any path other than `/` and we use HEAD so no content is downloaded.

## Check B — `dns_poisoning`

| Property | Value |
|---|---|
| Category | `PROBES` |
| Inputs | same domain list as Check A |
| Method | resolve via `InetAddress.getAllByName` AND via Cloudflare DoH JSON; compare answer sets |
| Severity rule | HARD if any blocked domain resolves to the real (DoH-confirmed) IP via system resolver; PASS if all are poisoned (RFC1918, NXDOMAIN, or operator landing page) |
| Per-source details | one row per domain: `system: <ip(s)> · doh: <ip(s)> · classification` |
| Files to touch | new `detect/probes/DnsPoisoningProbe.kt`, new `net/DohClient.kt` |

**Ground-truth resolver.** Cloudflare DoH JSON endpoint:
```
GET https://cloudflare-dns.com/dns-query?name=<domain>&type=A
Accept: application/dns-json
```
Returns `{"Answer":[{"name":"...","type":1,"data":"<ip>"},...]}`. If `cloudflare-dns.com` itself is unreachable (TSPU SNI block), fall back to `https://1.1.1.1/dns-query` (same JSON, IP-only SNI). If both fail mark the check `INFO: ground-truth unreachable` and skip the comparison rather than guess.

**Classification table:**

| System resolver answer | Classification | Per-row severity |
|---|---|---|
| Empty / NXDOMAIN / SERVFAIL | poisoned-NXDOMAIN | PASS |
| RFC1918 (10/8, 172.16/12, 192.168/16) | poisoned-landing | PASS |
| Single non-RFC1918 IP not in DoH set | hijack-to-third-party | SOFT |
| One or more IPs ⊆ DoH set | bypass | HARD |

**Caveat / overlap with `private_dns`.** A device with Private DNS = `1.1.1.1` will trivially bypass operator DNS, and that's already detected by the System tab's `private_dns` row. To avoid double-counting, this check should explicitly note in its `explanation` that "Private DNS active" already implies bypass and the row is here to catch the **other** bypass paths (router-side resolver over VPN, in-app DoH in a per-app tunnel, etc.).

## Check C — `router_egress_country` (traceroute)

| Property | Value |
|---|---|
| Category | `PROBES` |
| Inputs | foreign anchor IP `1.1.1.1`, max TTL 15 |
| Method | `Runtime.exec("/system/bin/ping -t N -c 1 -W 1 -n 1.1.1.1")` for N=1..15, parsed |
| Severity rule | HARD if first **public** hop's country ≠ SIM country |
| Per-source details | one row per hop: `[hop=N] <ip> → <country>, <asn org>` |
| Files to touch | new `detect/probes/Traceroute.kt`, register in `DetectorEngine` |

**Why `ping` and not raw sockets.** Android does not expose a public API to set unicast TTL on a `DatagramSocket`. The unprivileged ICMP socket in the kernel (`net.ipv4.ping_group_range`) is what the system `ping` binary uses, so shelling out is the only fully supported, root-free, vendor-independent path. Reflection-based `Os.setsockoptInt` works but is fragile across OEM ROMs.

**Parser.** The two output line shapes we care about:
```
From 192.168.86.1 icmp_seq=1 Time to live exceeded
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=12.3 ms
```
A simple regex `(?:From\s+)?(\d{1,3}(?:\.\d{1,3}){3})` per line plus a flag for "this was the final reply".

**Hop classification:**

| Hop | Expected on a clean RU device | Failure mode = HARD |
|---|---|---|
| 1 | RFC1918 (your router LAN IP) | n/a |
| 2 | First public hop, GeoIP=RU, ASN=local ISP | GeoIP ≠ RU → router-level VPN egress |
| 3+ | Various RU/foreign transit providers | n/a (informational only) |

**GeoIP lookup batching.** Each unique non-RFC1918 hop IP is looked up via `ipinfo.io/<ip>/json` once per run, deduped. Adds ~3-5 HTTP calls on top of the existing GeoIP probes — well under any rate limit.

**Time budget.** 15 TTL probes × 1 s timeout, but we run them in parallel via coroutines (`coroutineScope { (1..15).map { async { ping(it) } }.awaitAll() }`), so wall time ≈ max(slowest ping) ≈ 1-2 s plus the GeoIP lookups.

**Caveats.**
- Some cellular operators drop ICMP TTL exceeded entirely. We get `* * *` for every hop. Surface as `INFO: traceroute returned no hops`, do not contribute to score.
- ICMP path may differ from TCP path on multi-path links — true in datacenters, almost never on residential.
- Do not traceroute to RU domestic anchors — they may not be reachable from a foreign exit and the result is noise.

## Cross-signal correlation matrix

Once all three are implemented, the verdict explainer can produce qualitative diagnoses, not just a score:

| `sim_vs_ip` | `blocked_domain_reach` | `dns_poisoning` | `router_egress_country` | Diagnosis |
|---|---|---|---|---|
| FAIL | FAIL | FAIL | FAIL | Router-side full-tunnel VPN with high confidence |
| FAIL | PASS | PASS | PASS | GeoIP DB lag — false positive on a clean device |
| FAIL | FAIL | PASS | PASS | Per-app or in-browser DoH proxy (not a network VPN) |
| FAIL | PASS | FAIL | PASS | Private DNS to a foreign DoT/DoH provider, traffic still RU |
| PASS | FAIL | FAIL | n/a | Local app-level proxy (e.g. Outline) bypassing without changing exit IP visible to GeoIP |
| PASS | PASS | PASS | PASS | Clean device on a clean network |

This matrix is the real value of the new checks: it turns the existing single-axis "DETECTED / SUSPICIOUS / CLEAN" verdict into a categorised diagnosis, which is what an anti-fraud QA engineer actually wants to see.

## Implementation order

1. **Check B (`dns_poisoning`)** first — it has no extra runtime deps, no shelling out, and proves the JSON-DoH client.
2. **Check A (`blocked_domain_reach`)** second — same OkHttp client we already use, just three new HEAD requests.
3. **Check C (`router_egress_country`)** last — needs ICMP shelling logic, the most surface area for OEM-ROM oddities.

Each check should be added behind a `Severity = INFO` first run on a real RU device to validate the thresholds before promoting to HARD/SOFT.
