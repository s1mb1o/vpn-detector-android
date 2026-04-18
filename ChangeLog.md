# ChangeLog

## 2026-04-18 — Full Russian localization (UI + all check rows)

Extracted every hardcoded user-facing string to `res/values/strings.xml`
and added a parallel `res/values-ru/strings.xml`. Covers UI chrome,
severity / verdict / matrix labels, all ~50 check labels and their
multi-sentence explanations, generic value tokens (`none`, `off`, `n/a`,
`ERROR:`), per-source detail entries, STUN / reference-parity /
traceroute strings, share-text output, and history screen.

Device-language detection works via Android's standard resource
resolution, so on a `ru-RU` device every row renders in Russian.
Technical identifiers (`TRANSPORT_VPN`, `MCC`, `ASN`, `DNS`, etc.) stay
English since they are API terms.

Architecture:
- New `VpnDetectorApp` Application class + `AppStrings` singleton for
  resource access from `detect/` code without threading `Context`
  through every function.
- `detect/` Check-constructing code now resolves labels / explanations
  via `AppStrings.get(R.string.xxx)`; UI resolves via `stringResource`.

## 2026-04-18 — Documented HOST_REACHABILITY research review and parity gaps

Reviewed a public write-up of a reference RU-messenger `HOST_REACHABILITY`
anti-fraud telemetry pipeline (source-app build 26.12.1 as of 2026-04)
and compared its claimed VPN/IP/host checks with the current Android app.

- Added a new ResearchLog entry summarizing what the research shows
  reliably: six IP endpoints, five active host-reachability targets,
  foreground trigger, payload shape, retry queue, and call-time VPN UI.
- Recorded the main caveat: the research does not show the internals
  of the `vpn` bit itself, only the call site. The safest interpretation
  remains that the reference app uses the standard Android local-VPN
  signal (`TRANSPORT_VPN`), with the real value coming from server-side
  correlation of IP + operator + host reachability + account context.
- Recorded the parity gap list for a future "host-reachability mode":
  exact five-host reachability, exact six-endpoint first-success IP
  collector, optional raw-socket probing, and
  `HOST_REACHABILITY`-shaped payload export.

## 2026-04-15 — Router-VPN signals: v4/v6 split, DNS leak, STUN

Three new detections targeting the router-side VPN scenario, where
device-local flags (`TRANSPORT_VPN`, `tun*`, `VpnTransportInfo`) are
structurally blind because the tunnel terminates on the gateway, not
the phone.

- `v4_v6_exit_split` (Consistency): geolocates the IPv6 exit via a
  new `ip-api-v6` probe and compares country/ASN to the v4 HTTP exit.
  Country mismatch = HARD, ASN mismatch = SOFT. Catches the common
  case of a router that only tunnels v4, leaving v6 on the native ISP.
- `dns_vs_exit` (Consistency): new `resolver-egress` probe resolves
  `whoami.akamai.net` via the system DNS resolver — Akamai's
  authoritative server returns an A record equal to the recursive
  resolver's egress IP, which is then geolocated. Country mismatch
  with the HTTP exit = HARD (DNS leak or port-53 interception).
- `stun_mapped_vs_exit` (Probes): RFC 5389 STUN Binding Request to
  `stun.l.google.com:19302`, parses XOR-MAPPED-ADDRESS, compares to
  the v4 HTTP exit. Mismatch = HARD (WebRTC/UDP bypassing the tunnel).
  No STUN response = INFO (UDP blackholed upstream, indeterminate).

Supporting changes:
- `ProbeResult` gained `isIpv4` / `isIpv6` helpers.
- `GeoIpProbes.derive()` excludes the two new specialty probes from
  aggregation checks (`asn_class`, `reputation_flag`,
  `probe_ip_agreement`, `probe_country_agreement`, `external_country`)
  — they describe different egresses by design and would otherwise
  trip those checks spuriously. Same fix removes a pre-existing
  false-positive where `yandex-v6` counted against v4 IP agreement.

## 2026-04-15 — Multi-target traceroute + additional GeoIP probes

`router_egress_country` now probes three anchors in parallel:
`1.1.1.1` (Cloudflare), `8.8.8.8` (Google DNS), `77.88.8.8`
(Yandex DNS, RU). Aggregate verdict is worst across targets;
per-target hop detail is grouped in the expanded view.

Split/whitelist-routing setups (RU destinations local, foreign
tunnelled) are now directly visible — the RU target stays PASS while
the foreign targets go HARD. Previously a single 1.1.1.1 target
couldn't distinguish "full VPN" from "whitelist routing".

## 2026-04-15 — Additional GeoIP probes

Added five more external-IP probes mirroring the checkers documented
in public RU anti-fraud research:

- `yandex-v4` — ipv4-internet.yandex.net
- `yandex-v6` — ipv6-internet.yandex.net (only endpoint that surfaces
  IPv6 reachability)
- `ifconfig.me` — independent, plain-text `/ip`
- `aws-checkip` — checkip.amazonaws.com, Amazon
- `ip.mail.ru` — Mail.ru / VK Group (HTML, IP extracted via regex)

Each probe contributes to the existing `probe_ip_agreement` and
transparent-proxy-header checks. `api.ipify.org` was already wired
(provider `ipify`) and unchanged.

## 2026-04-10 (release v0.5.0) — Anti-detection toolchain, cellular & GeoIP fixes

New checks (System tab):
- `anti_detection_toolchain` — detects rooted/Xposed/Frida/Magisk
  environments commonly used to hide VPN presence from apps. Severity
  HARD when any toolchain component is found.

Fixes:
- GeoIP: whitelist known service-side proxy header markers to reduce
  false positives from CDN-injected headers.
- Probes: demote latency-based checks on cellular networks where high
  jitter causes spurious SOFT/HARD signals.

Docs:
- `docs/knowledge-base/` — consolidated research and operator know-how
  (threat model, router blueprint, operator playbook, ADR-001
  whitelist routing).
- `docs/specs/06_hiding-strategies.md` — how to lower the detection
  score on a real device.

versionCode 4 → 5, versionName 0.4.0 → 0.5.0.

## 2026-04-07 (release v0.4.0) — Methodology v2 coverage pass

Closes most of the gap between our catalog and the published anti-fraud
methodology document (`docs/specs/05_metrics-review.md` is the full
review and a per-check mapping back to the methodology).

New checks (System tab):
- `tun_iface` / `active_iface_name` / `default_route_tun` now also match
  `ipsec*` interfaces (methodology §6.4 mentions IKEv2/IPsec).
- `jvm_proxy` — System.getProperty(http.proxyHost / https.proxyHost /
  socksProxyHost). Per-process proxies that LinkProperties.httpProxy
  does not see. HARD when any host is set.
- `vpn_transport_info` — API 31+ NetworkCapabilities.transportInfo
  decoded as VpnTransportInfo, exposing the active VPN session id and
  bypassable flag (methodology §6.4).
- `route_anomalies` — counts default routes and routes via tunnel
  interfaces (methodology §7.6). Per-source DetailEntry breakdown.
- `dumpsys_vpn` — best-effort `Runtime.exec(/system/bin/dumpsys
  vpn_management)` shell-out to enumerate active VPN packages on
  Android 12+ (methodology §7.4). Falls back to INFO on a regular uid.
- Extended `KNOWN_VPN_PACKAGES` with ByeDPI, Orbot/Tor, Intra,
  ProxyDroid, AdGuard VPN, and a few others (methodology §6 + §7.8).

New checks (Probes tab):
- `local_proxy_listeners` (new file `LocalListenerProbe.kt`) —
  TCP-connects to 127.0.0.1 on every methodology-listed proxy port
  (SOCKS 1080/9000/9050/9051/9150, HTTP 3128/8080/8888,
  transparent 4080/7000/7044/12345, Shadowsocks/V2Ray local 1081/1086).
  Any successful connect = a proxy is running on the device. Bypasses
  the Android-10+ SELinux block on /proc/net/tcp enumeration.

New checks (GeoIP tab):
- `transparent_proxy_headers` — methodology §10.2. Inspects every
  GeoIP probe response for Via / X-Forwarded-For / Forwarded /
  X-Real-IP. Since OkHttp talks to the GeoIP services with
  Proxy.NO_PROXY, any of these headers means a transparent middlebox
  is rewriting traffic in flight. HARD on any hit.
- `asn_class` — CDN whitelist (methodology §4 false-positive mitigation).
  Cloudflare/Akamai/Fastly/CloudFront/Google/Incapsula/StackPath etc.
  org-name match demotes the row from HARD to INFO so legitimate
  CDN-fronted apps stop firing.
- `country_history` — methodology §5.4 step 5. Compares the current
  external_country to the most recent prior run. <1h gap = HARD,
  <12h = SOFT, otherwise INFO.

New decision-matrix verdict label (methodology §9 Table 2):
- New `MatrixLabel` enum and three new fields on `Verdict`
  (`matrix`, `matrixGeoip`, `matrixDirect`, `matrixIndirect`).
  Each axis fires on any HARD signal in its category set. The
  three-class label (BYPASS_NOT_DETECTED / NEEDS_REVIEW /
  BYPASS_DETECTED) is derived directly from the methodology's
  decision matrix and runs alongside the existing scalar verdict.
- VerdictBar UI shows the label and per-axis booleans.
- Share text and logcat dump now include the matrix label.

Engine wiring:
- `DetectorEngine.runAll` takes a new optional `previousRun`
  parameter for the history check.
- Five categories now run in parallel: SystemChecks + GeoIpProbes +
  ConsistencyChecks + ActiveProbes + Traceroute + LocalListenerProbe,
  plus HistoryChecks at the end.
- `AppViewModel.runAll` reads the most recent prior run from the
  repository and passes it to the engine.

Docs:
- `docs/specs/05_metrics-review.md` — comprehensive per-check review.
  Every detection metric documented with: methodology source paragraph,
  what it tests, severity rule, false-positive sources, mitigations,
  code reference, and known limitations.
- ChangeLog entry above.

versionCode 3 → 4, versionName 0.3.0 → 0.4.0.

## 2026-04-07 (release v0.3.0) — Check C: router-egress traceroute

Implements proposed Check C from `docs/specs/04_proposed-checks.md`:
maps the L3 path to a foreign anchor (1.1.1.1) using the unprivileged
ICMP socket via `/system/bin/ping -t N`, GeoIP-resolves every public
hop, and flags HARD when the first non-RFC1918 hop's country differs
from the SIM country — i.e. the device is exiting through a router-side
VPN tunnel.

Validated against the real Pixel 8 + home-router setup in the previous
session: hop 1 = 192.168.86.1 (LAN gateway), hops 2-3 = RFC1918 inside
the router (Docker bridge + WG/AWG client), hop 4 = 78.128.99.1 BG
Sofia AS203380 — first public hop ≠ SIM country (RU). Detection
condition fires correctly on this network.

Implementation notes:

- New `detect/probes/Traceroute.kt`. Spawns 15 parallel `/system/bin/ping
  -c 1 -W 1 -n -t N` processes via coroutines, parses both
  `From X.X.X.X` (TTL exceeded) and `bytes from X.X.X.X` (final reply)
  lines with one regex, trims hops past the first final reply.
- Per-hop GeoIP lookup via `ipinfo.io/<ip>/json`, deduped on unique
  public IPs. Adds ~3-5 HTTP calls per run.
- RFC1918 detection inline (10/8, 172.16-31/16, 192.168/16, 169.254/16,
  127/8, plus CGNAT 100.64/10).
- Wired into `DetectorEngine.runAll` as a fourth parallel async block.
- New row `router_egress_country` in PROBES tab. Severity rule:
  - HARD: first non-RFC1918 hop country ≠ SIM country
  - PASS: first non-RFC1918 hop country == SIM country
  - INFO: traceroute returned no hops, or SIM country unknown
- Per-hop DetailEntry rows in the details dialog: `hop N: <ip>
  <country> <city> <org>`, severity per hop (HARD only on the
  first-public mismatch row, INFO on private hops, PASS on matching
  hops).
- versionCode 2 → 3, versionName 0.2.0 → 0.3.0.

## 2026-04-07 (release v0.2.0)

First shareable build. APK at `app/build/outputs/apk/release/app-release.apk`,
sha256 84b99c59ddcee8a76f0ede754eaf1232460ccffa576e7ac6549101d5f3d9dadf.

- Package renamed `ru.shmelev.vpndetector` → `net.vpndetector` to remove
  developer name from the APK and from `pm list packages`. Source tree moved
  from `app/src/main/kotlin/ru/shmelev/vpndetector/` to
  `app/src/main/kotlin/net/vpndetector/`.
- Release signing config: `keystore/release.jks` (gitignored) with anonymous
  identity `CN=vpn-detector-anon, O=anonymous, C=ZZ`. Credentials read from
  `keystore.properties` (also gitignored). Falls back to debug-signing on a
  fresh checkout without secrets.
- R8 minification + resource shrinking enabled for release builds. ProGuard
  rules added to keep kotlinx.serialization, OkHttp, Compose intact.
- versionCode 1 → 2, versionName 0.1.0 → 0.2.0.
- New PRIVACY.md and RELEASE.md.
- Telegram presence check added to System tab (weak signal).
- Share icon in the verdict bar — exports the run as markdown via the system
  share sheet.
- Per-source DetailEntry breakdown for reputation_flag, asn_class,
  probe_ip_agreement, lat_ru, lat_foreign, lat_ratio.
- Tap row → details dialog with full check info.

## 2026-04-07 (evening) — emulator validation

End-to-end run on Pixel 3a API 34 emulator. App builds, installs, all 4 detection
tabs and History render correctly. Verdict logic verified: emulator (US SIM, BG
exit IP via host) is correctly classified as DETECTED with 5 hard / 2 soft signals
(SIM↔IP, network↔IP country mismatches, RU latency, latency ordering, probe
reputation flag).

- Removed `underlying_networks` check — `NetworkCapabilities.getUnderlyingNetworks()`
  is `@SystemApi`/hidden, not callable from a regular app (compile error). The
  signal is already covered by `transport_vpn` + `tun_iface`.

## 2026-04-07 (afternoon) — review fixes from codex + gemini

- **Manifest**: hoist `xmlns:tools` to root `<manifest>` (was on `<application>`, broke parsing of `tools:ignore` on a sibling permission).
- **SystemChecks**: fix nullable `interfaceName` compile error in MTU branch; degrade `cap_not_vpn` to INFO when there is no active network (offline ≠ DETECTED).
- **Cleartext probes**: add `network_security_config.xml` allowing HTTP only for `ip-api.com` (free tier is HTTP-only) and `connectivitycheck.gstatic.com` (captive-portal probe must be HTTP by design). All other traffic stays HTTPS-only.
- **AppViewModel**: catch exceptions in `runAll`, expose `error` StateFlow; use `SharingStarted.WhileSubscribed(5_000)` instead of `Eagerly` for history.
- **ActiveProbes**: parallelize latency probes (`medianLatencyParallel`) — was sequential, blocked IO thread up to 12s on degraded networks.
- **MainActivity**: only request permissions once (skip on configuration-change recreations and when already granted).
- **ConsistencyChecks**: drop `READ_PHONE_STATE` gating — `simCountryIso`/`networkCountryIso`/`networkOperator(Name)` do not require it; remove from manifest.
- **Compose**: switch to `collectAsStateWithLifecycle()` (added `androidx-lifecycle-runtime-compose` dep).
- **Gradle wrapper**: commit `gradlew`, `gradlew.bat`, `gradle-wrapper.jar` so the documented build command works on a clean checkout.

## 2026-04-07

Initial scaffold of vpn-detector-android.

- Gradle project (Kotlin DSL, version catalog), AGP 8.7, Kotlin 2.0, Compose BOM 2024.11.
- App module `ru.shmelev.vpndetector`, minSdk 26, targetSdk 35.
- Detect engine: `Check`, `Severity`, `Verdict`, `VerdictAggregator`, `DetectorEngine` orchestrator.
- `SystemChecks` — TRANSPORT_VPN, NET_CAPABILITY_NOT_VPN, tun/wg/ppp interface enumeration, default-route via tunnel + WG split-route trick, underlyingNetworks (API 31+), HTTP proxy, Private DNS, DNS servers, MTU, always-on VPN, installed VPN packages, mock location, dev options/ADB, root indicators, Wi-Fi SSID.
- `GeoIpProbes` — parallel ipify/ipinfo/ip-api/ifconfig.co/myip.com/cf-trace; ASN datacenter classification; reputation flag aggregation; probe disagreement detection.
- `ConsistencyChecks` — SIM/network country, carrier name vs ASN, MCC vs IP country, locale, language, timezone, RU app fingerprint.
- `ActiveProbes` — RU vs foreign latency anchors, IPv6 reachability, captive portal probe, local address enumeration.
- `RunRepository` — DataStore-Preferences history (last 50 runs).
- Compose UI: persistent verdict bar, 5 bottom-nav tabs (System / GeoIP / Consistency / Probes / History), FAB for "Run all checks".
