# ResearchLog

## 2026-04-18 (HOST_REACHABILITY research review)

### Source under review

- Public RU technical write-up on a reference RU-messenger anti-fraud
  telemetry pipeline (`HOST_REACHABILITY` collector, IP discovery, VPN
  bit, state-service reachability checks).
- Publication date on page: `2026-04-12`
- Reference-app build stated by the author: `26.12.1`

### What the article shows reliably

- On foreground/open, the reference app runs a `HOST_REACHABILITY` pipeline and uploads a payload containing:
  - `hosts` reachability booleans
  - `operator`
  - `connection_type`
  - `ip`
  - `vpn`
- Active reachability host set shown in the article:
  - `api.oneme.ru`
  - `gstatic.com`
  - `calls.okcdn.ru`
  - `gosuslugi.ru`
  - `mtalk.google.com`
- IP-discovery endpoints shown in the article:
  - `ipv4-internet.yandex.net`
  - `ipv6-internet.yandex.net`
  - `ifconfig.me`
  - `api.ipify.org`
  - `checkip.amazonaws.com`
  - `ip.mail.ru`
- The article also shows:
  - randomization of the IP-service order (`Collections.shuffle`)
  - first-success-wins semantics for IP discovery
  - durable retry / local queueing for telemetry delivery
  - call-time UI/analytics state for "VPN detected" (`VpnPanelWidget`, `BAD_CONNECTION_ALERT`)
  - dormant Telegram / WhatsApp reachability constants (`main.telegram.org`, `mmg.whatsapp.net`) that are not in the active check list

### What the article does NOT prove cleanly

- The exact implementation of the `vpn` bit is not shown. The post only shows the call site:
  - `if (((nc4) b19Var.getValue()).e()) { ro9Var.put("vpn", 1); }`
- Therefore, "how the reference app detects VPN" in this article is partly inference.
- The strongest corroboration we already have is an older local analysis
  of an earlier build that found the canonical getter to be:
  - `NetworkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)`
- Safest conclusion:
  - the client-side VPN flag is probably still a standard Android local-VPN signal
  - the operationally important part is the surrounding telemetry correlation: external IP, host reachability, operator, connection type, timestamp, account binding

### Comparison with this app

Our app already exceeds the article's likely client-side VPN detection depth in several areas:

- Direct Android VPN/proxy signals:
  - `TRANSPORT_VPN`
  - `NET_CAPABILITY_NOT_VPN`
  - tunnel interface enumeration (`tun*`, `wg*`, `ppp*`, `ipsec*`)
  - active interface name
  - default route via tunnel / WireGuard split-route signature
  - HTTP proxy and JVM proxy properties
  - `VpnTransportInfo`
  - `dumpsys vpn_management`
- Indirect on-device signals:
  - public DNS / Private DNS
  - always-on VPN
  - installed VPN and anti-detection toolchain packages
  - MTU and route anomalies
  - Telegram presence
- Cross-checks and network probes beyond the article:
  - ASN / hosting / reputation classification
  - SIM / MCC / carrier / locale / timezone consistency
  - RU-apps fingerprint
  - IPv4-vs-IPv6 exit split
  - DNS-resolver-egress vs HTTP-exit mismatch
  - STUN mapped address vs HTTP exit
  - multi-target traceroute for router-side VPN detection
  - transparent proxy header detection

### Gaps if the goal is exact reference fidelity

If the goal is "mirror the reference pipeline specifically", not merely "detect VPN better", the main missing pieces are:

1. Exact `HOST_REACHABILITY` host set and per-host boolean check
   - We currently probe generic RU/foreign anchors for latency, not the reference five concrete hosts.

2. Exact reference IP-selection semantics
   - We run all probes in parallel and keep the full disagreement matrix.
   - The reference appears to shuffle six endpoints and keep the first successful answer.

3. Raw-socket IP probe mode
   - The article claims the reference uses `java.net.Socket` rather than OkHttp for the IP check path.
   - Our probes use OkHttp, which is better for diagnostics but not identical under proxy/MITM conditions.

4. Foreground trigger semantics
   - Our app runs on explicit user action.
   - The reference appears to trigger on app foreground when the feature flag is enabled.
   - Intentionally excluded from parity scope for this project.

5. Reference-shaped payload export / replay
   - We do not currently construct or export a diagnostic object equivalent to:
     `HOST_REACHABILITY { hosts, operator, connection_type, ip, vpn }`

6. Call-time VPN-warning modeling
   - No equivalent of the in-call VPN-warning UI / analytics events
   - Useful only if we want parity with reference behavior during calls

### Recommendation

- If the product goal is "best-effort anti-fraud / anti-VPN detector", current coverage is already broader than the article.
- If the product goal is "reference emulator / oracle", add a dedicated parity mode:
  - exact five-host reachability row
  - exact six-endpoint IP collector with first-success-wins and optional shuffle
  - optional raw-socket collector implementation
  - exportable `HOST_REACHABILITY`-shaped JSON payload for comparison
- Lowest-value additions:
  - dormant messenger-reachability domains from the article
  - guaranteed-delivery queueing (useful for telemetry reproduction, not for detection quality)

## 2026-04-07 (proposed signals — research)

### 1. Blocked-domain HTTP reachability

**Idea.** The RU state-level TSPU DPI blocks a public, well-known list of foreign sites at the operator level (DNS poisoning + SNI-based DPI reset). If the device successfully completes a TLS handshake with any of these from a RU connection, something on the path is bypassing the block — most plausibly a router-level VPN exit, a per-app proxy, or a DoH-aware browser used as a tunnel.

**How to probe from the app:**
- Maintain a small fixed list of long-blocked-in-RU foreign domains. Public, undisputed, on the RU state block list for years: `linkedin.com` (since 2016), `facebook.com` (since 2022), `instagram.com` (since 2022). Avoid anything that's only throttled or only sometimes blocked — we want unambiguous signals.
- For each, do a single OkHttp `HEAD https://<domain>/` with a 4-second timeout.
- Classify the outcome:
  - **2xx / 3xx** → reachable, almost certainly via bypass on a RU connection
  - **TLS handshake failure / connection reset mid-handshake** → typical TSPU SNI-RST → no bypass
  - **Connect timeout** → typical DNS poisoning to dead IP → no bypass
  - **DNS NXDOMAIN** → operator DNS poisoning the lookup → no bypass

**Severity rules:**
- Per-domain row in details: PASS if reachable, INFO if blocked-as-expected, WARN if ambiguous (slow, partial response).
- Aggregate: HARD if **all** probed domains succeed AND the GeoIP tab says we're on a RU IP. SOFT if 1-of-N succeeds. PASS if 0-of-N succeeds.

**Caveats.**
- Probes traverse the device's normal route, so if a foreign-DNS Private DNS or per-app split-tunnel is in use, the result is real. If nothing is bypassing, the request will fail naturally.
- We must not actually fetch any content from these sites; HEAD only, no body, no cookies. The OkHttp client already disables cookies.
- This signal is **legitimate from a QA perspective** (it tests "did my device's profile match the RU operator filtering policy") and equally valid from an anti-fraud SDK perspective (it tests "is the user evading the policy"). Same measurement, different label.

**Risk.** Hitting `linkedin.com` from a residential RU IP is not itself anomalous — it's what every user behind a corporate VPN already does. The probe is invisible to the operator beyond a TLS handshake to a public IP. We do not log into anything.

### 2. DNS-poisoning detection (system DNS vs ground-truth DoH)

**Idea.** RU TSPU returns spoofed answers from operator DNS for blocked domains — typically RFC1918 addresses, the ISP's "blocked content" landing page IP, or NXDOMAIN. If the device's system resolver returns the **real** public IP for one of those domains, the device is using a non-RU resolver — either DoH/DoT to Cloudflare/Google, a Private DNS over a VPN tunnel, or a router-side resolver that itself goes over VPN.

**How to probe from the app:**
- Pick the same small set of blocked domains as in (1).
- Resolve each via `InetAddress.getAllByName(domain)` — that's the system resolver, the same one any other app uses.
- In parallel, resolve each via DoH directly: POST `https://cloudflare-dns.com/dns-query` with a wire-format DNS query (RFC 8484), or for less code, GET `https://cloudflare-dns.com/dns-query?name=<domain>&type=A` with `Accept: application/dns-json`. Returns Cloudflare's authoritative-side answer in JSON.
- Compare the answer sets:
  - System answer ⊆ DoH answer set → **bypass** (system resolver returning the real IP, HARD)
  - System answer is RFC1918 (`10/8`, `172.16/12`, `192.168/16`) → **poisoned** (operator landing page, PASS)
  - System answer is null/SERVFAIL/NXDOMAIN → **poisoned** (PASS)
  - System answer is a non-RFC1918 IP that's NOT in the DoH answer set → **partially bypassed** or DNS hijack to a third party (SOFT)

**Severity rules:**
- Per-domain detail row: PASS (poisoned-as-expected) / FAIL (bypassed) / SOFT (anomalous).
- Aggregate: HARD if any blocked domain resolves to the real IP through system DNS.

**DoH client implementation notes:**
- The `application/dns-json` endpoint at `cloudflare-dns.com/dns-query` returns small JSON (`{"Answer":[{"name":"...","type":1,"data":"104.244.42.65"}, ...]}`). Trivial to parse with kotlinx.serialization.
- Cloudflare DoH itself is sometimes blocked at TSPU level (TLS SNI `cloudflare-dns.com`). Fall back to `1.1.1.1` over DoH (`https://1.1.1.1/dns-query`) — same content, IP-only SNI. If both fail, we mark the check `INFO: ground-truth unreachable` and skip the comparison rather than guessing.

**Caveats.**
- If the user has Private DNS set to a public DoT/DoH provider, system DNS *will* return the real IPs, but the device is by definition not using operator DNS. That's already covered by `private_dns` in System tab — we'd be reporting the same fact in two places. Mention it in the explanation but don't double-count in the score.
- A clean RU device with a VPN-on-router setup can have system DNS poisoned (operator) or clean (router DNS over VPN), depending on what the router serves. This check distinguishes the two configurations cleanly.

### 3. Traceroute / detect router-side VPN client (without root)

**Idea.** From the phone alone we can already see "this device has no local VPN" (System tab) and "but our exit IP is in BG" (GeoIP/Consistency tabs). What we cannot currently see: **where on the path the foreign exit is inserted**. A traceroute that maps the first ~5 hops + GeoIP-resolves each public hop directly answers "is the egress at the home router, the ISP, or somewhere else".

**The Android constraint.** Regular Android apps cannot create raw / ICMP sockets. The two viable paths:

**Path A — `ping` via `Runtime.exec` (recommended).**
- `/system/bin/ping` exists on every Android since at least 4.x and uses the unprivileged ICMP socket (kernel `net.ipv4.ping_group_range`), so it works without root and without setuid.
- It accepts `-t TTL` and `-c 1` (count) and `-W 1` (timeout), and prints lines like `From 192.168.86.1 icmp_seq=1 Time to live exceeded` for intermediate hops and `64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=12.3 ms` for the final reply.
- Loop TTL = 1..15, parse "From X.X.X.X" or final reply, terminate when reply received or 3 consecutive timeouts.
- Target: a known foreign anchor like `1.1.1.1` (low political risk, ICMP-friendly, doesn't rate-limit).
- Fork is short — each ping is one syscall + one parse. Run all 15 in parallel via coroutines.
- Validation: tested in similar Android utility apps; the binary location and output format are stable across vendor ROMs.

**Path B — DatagramSocket + reflection on FD + `android.system.Os.setsockoptInt(IPPROTO_IP, IP_TTL, ttl)`.**
- Java's public API does not expose unicast TTL. You can reach the underlying file descriptor via reflection on `DatagramSocketImpl` and then call `Os.setsockoptInt`. ICMP responses come back as ICMP unreachable / TTL exceeded which a UDP socket cannot directly read (kernel routes them to the error queue).
- Reading the error queue requires `Os.recvmsg` with `MSG_ERRQUEUE`, which exists in `android.system.Os` but is rarely used and has reflection-only access on older API levels.
- Strictly works, but fragile and harder to test on a range of devices. **Don't pursue unless Path A breaks.**

**Path C — TCP-based traceroute via `setSoTimeout` + `connect` + measuring failure type.**
- Open a TCP socket with `IP_TTL = N` to a foreign port-80 host. Intermediate routers reply with ICMP TTL exceeded; the TCP `connect` fails. We can't read the source IP of the ICMP reply through TCP. Doesn't actually give us hop addresses. **Useless for this purpose.**

**Recommendation: Path A.**

**Result interpretation:**
- For each hop, look up its IP via the same `ipinfo.io` probe we already use (cached batch — one HTTP call per unique IP).
- Hop 1 = default gateway (almost always a private RFC1918 — your router LAN IP). Confirms what we already see in `LinkProperties.routes`.
- Hop 2 = the first **public** hop. This is where the egress lives.
  - If hop 2 GeoIP country == SIM country → no router VPN, traffic exits at the local ISP. Clean.
  - If hop 2 GeoIP country != SIM country → **router VPN inserted between the home network and the public internet**. HARD signal.
  - If hop 2 is also private (10.0.0.0/8 or 100.64.0.0/10) → CGNAT or double-NAT, ambiguous, mark INFO and look at hop 3.
- The hop list itself is the most interesting per-source detail row: `[hop=1] 192.168.86.1 → home router` / `[hop=2] 91.148.x.x → BG, AS203380`.

**Severity rules:**
- HARD: first public hop's country differs from SIM country
- SOFT: traceroute completes but the path is "too short" (≤2 public hops to a foreign anchor) — possible split-tunnel
- INFO: traceroute fails to start (some operators drop ICMP TTL exceeded entirely)

**Caveats.**
- Some carrier networks rate-limit or drop ICMP TTL exceeded altogether, so the trace returns `* * *` for some hops. Tolerate that — partial traces are still useful.
- A wall time budget: 15 hops × 1s timeout × parallel = ~3 seconds added per run. Acceptable.
- ICMP traceroute does not necessarily traverse the same path as TCP/UDP traffic on multipath links, but for residential setups it almost always does.
- Don't traceroute to RU domestic anchors — they may not be reachable through the foreign exit and the result will be noise.

### Cross-signal correlation

The three new checks reinforce each other and the existing Consistency tab:

```
SIM=RU, IP=BG (existing)
+ blocked domains reachable        → router-level bypass
+ blocked domains resolve to real IPs via system DNS → DNS bypass (router or device)
+ traceroute hop 2 = BG → router-level bypass confirmed at L3
```

If all three new checks fire alongside the existing Consistency `sim_vs_ip` HARD, the verdict is "router-side VPN with high confidence" rather than just "something doesn't add up". For a QA harness this is the difference between a generic DETECTED and a categorised diagnosis.

### Open questions still

- True DNS leak test requires a controlled authoritative domain. Deferred until we register one.
- Is `Settings.Secure.always_on_vpn_app` readable on Android 14 without privileged perm? (Some OEM ROMs restrict.)
- Detecting Magisk Hide / Zygisk reliably from a non-root app — limited; current implementation is heuristic only.

### Validation: Check C (`/system/bin/ping -t N`) on real device

Two runs on Pixel 8 (API 35) over USB to validate Path A.

`/system/bin/ping` is present, owned by `root:shell`, mode `755`. `/proc/sys/net/ipv4/ping_group_range` is `0 2147483647` — every uid can use the unprivileged ICMP socket. No setuid bit, no root, no special permission needed.

#### Run 1 — phone has its own WireGuard client active

```
hop  1: 172.30.0.1   ← phone's wg tun interface
hop  2: 172.17.0.12  ← (inside the home router)
hop  3: 10.10.0.1    ← (inside the home router)
hop  4: 78.128.99.1  ← BG Sofia · AS203380 DA International Group Ltd.
hop  5: 10.0.1.1
hop  6: 94.72.150.178
hop  7: 178.132.82.74  ← BG Sofia · AS57344 Telehouse EAD
hop  8: 178.132.81.234
hop  9: 1.1.1.1
```

The first hop is `172.30.0.1`, the WireGuard tunnel interface on the phone itself, **not** the LAN gateway `192.168.86.1`. This is itself the diagnostic for the phone-side VPN — and is already covered by `transport_vpn` and `tun_iface` in System tab. The route table at this point had the default route in a separate routing table belonging to the wg interface.

#### Run 2 — phone-side VPN disabled, only home-router VPN remains

```
hop  1: 192.168.86.1  ← home router LAN side ✓
hop  2: 172.17.0.12   ← Docker default bridge inside the router
hop  3: 10.10.0.1     ← AmneziaWG / WG client interface inside the router
hop  4: 78.128.99.1   ← BG Sofia · AS203380 DA International Group Ltd.
hop  5: 10.0.1.1      ← in-tunnel hop on the upstream provider
hop  6: 94.72.150.178 ← BG Sofia
hop  7: 178.132.82.74 ← BG Sofia · AS57344 Telehouse EAD
hop  8: 178.132.81.234
hop  9: 1.1.1.1
```

Route table now cleanly says `default via 192.168.86.1 dev wlan0 table 1047`.

#### What Run 2 confirms

- Hop 1 = `192.168.86.1` is the expected LAN gateway. PASS.
- Hops 2-3 are RFC1918 ranges that the LAN gateway forwards into. They are *inside* the router box — the `172.17.0.0/16` subnet is the Docker default bridge (the router runs containers), `10.10.0.0/24` is one of the WG/AWG client interfaces. This is a unique fingerprint: a normal residential router decrements TTL once and the next hop is the ISP. **Two consecutive RFC1918 hops after the LAN gateway is the signature of a router running tunnel containers.**
- Hop 4 is the **first non-RFC1918 hop**, in **BG Sofia, AS203380**. The phone's SIM is RU (MegaFon, MCC 250). `first_public_hop_country != sim_country` → **HARD signal for Check C**, exactly as the spec describes.
- Hop 5 (`10.0.1.1`) being RFC1918 *between* two BG public hops is also informative — it's the in-tunnel address space of the upstream VPN provider. Not used by the rule directly, just an interesting observation.
- The visible exit IP (`91.148.132.84`, also AS203380) doesn't appear in the trace because it's the SNAT public face, not a forwarding hop on the way to `1.1.1.1`. Same ASN though, so the story is consistent.

#### Implementation notes from validation

- The `From X.X.X.X icmp_seq=1 Time to live exceeded` and `64 bytes from X.X.X.X` line shapes were parseable in both runs with a single regex. No surprises.
- 9 hops × ~1 s timeout each = ~9 s wall time when run sequentially. Implementing with `coroutineScope { (1..maxTtl).map { async { ping(it) } } }` brings this down to ~1-2 s.
- The rule `first_non_RFC1918_hop_country != sim_country` works correctly for both runs. The spec phrasing "hop 2" must be replaced with "first non-RFC1918 hop" — already noted in `04_proposed-checks.md`.
- A re-runnable shell version of this validation lives at `tools/traceroute.sh`. Use it after every router-side change to verify the new path without rebuilding the APK.

## 2026-04-07

### Android VPN detection APIs (current)

- `ConnectivityManager.getNetworkCapabilities(activeNetwork).hasTransport(TRANSPORT_VPN)` — primary signal, available since API 21.
- `NetworkCapabilities.hasCapability(NET_CAPABILITY_NOT_VPN)` — mirror.
- `NetworkCapabilities.getUnderlyingNetworks()` — API 31+, returns the networks a VPN is built on top of. Non-empty = current network IS a VPN.
- `LinkProperties.routes` — checking for `0.0.0.0/0` via tun is the canonical "default route via VPN" check. Note WireGuard's `0.0.0.0/1` + `128.0.0.0/1` split-route trick on Android.
- `LinkProperties.privateDnsServerName` — DoT hostname when Private DNS is set explicitly.
- `NetworkInterface.getNetworkInterfaces()` — enumerate `tun*`, `tap*`, `wg*`, `utun*`, `ppp*`. Visible without `READ_PHONE_STATE`.

### GeoIP probe endpoints (free, no auth)

- `https://api.ipify.org?format=json` — IP only
- `https://ipinfo.io/json` — IP, country, region, city, org, timezone
- `http://ip-api.com/json/?fields=...` — adds `proxy`, `hosting`, `mobile` flags. Rate-limited to 45 req/min from a single IP.
- `https://ifconfig.co/json` — IP, country, ASN, ASN org, time_zone
- `https://api.myip.com` — IP, country, country_code
- `https://www.cloudflare.com/cdn-cgi/trace` — plain text k=v; reveals `warp=on` for Cloudflare WARP.

### Known datacenter ASN keywords (org-name substring match)

DigitalOcean, Amazon/AWS, Hetzner, OVH, Linode, Vultr/Choopa, Google Cloud, Microsoft/Azure, M247, Quadranet, Leaseweb, Cloudflare, DataCamp, Contabo, Scaleway, Online SAS.

### Open questions / future research

- True DNS leak test requires a controlled authoritative domain. Deferred until we register one.
- Is `Settings.Secure.always_on_vpn_app` readable on Android 14 without privileged perm? (Some OEM ROMs restrict.)
- Detecting Magisk Hide / Zygisk reliably from a non-root app — limited; current implementation is heuristic only.
