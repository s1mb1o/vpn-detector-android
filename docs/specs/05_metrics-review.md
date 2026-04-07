# Metrics Review — every detection check, audited

Comprehensive per-check audit of the detection catalog as of v0.4.0. For every row produced by the engine: what it tests, the methodology paragraph it implements, the rule we use, the known false-positive sources, our mitigations, the code reference, and the limitations.

The reference methodology document throughout is the published anti-fraud research summarised in [`source-methodology.md`](source-methodology.md). Section numbers below cite that document.

Severity model recap (`detect/Check.kt`, `detect/Verdict.kt`):

- **HARD** — single occurrence is enough for an anti-fraud SDK to mark VPN with high confidence. Score weight 100.
- **SOFT** — contributes to a score; multiple SOFT hits aggregate to a verdict. Score weight 10.
- **INFO** — neutral diagnostic, never affects the score.
- **PASS** — observed value matches a clean profile, never affects the score.

Aggregation: `score = 100·HARD + 10·SOFT`. `≥100 → DETECTED`, `≥30 → SUSPICIOUS`, else `CLEAN`.

In addition the v0.4.0 methodology decision-matrix label (`MatrixLabel` in `Verdict.kt`) groups checks into three axes and reports the three-class verdict from §9 Table 2. The `Methodology axis` column below records which axis each check belongs to.

---

## SYSTEM tab — direct on-device signals

Methodology §6.4 (Android direct signals) and §7.4 (Android indirect signals).
File: [`detect/system/SystemChecks.kt`](../../app/src/main/kotlin/net/vpndetector/detect/system/SystemChecks.kt)

### `transport_vpn` — TRANSPORT_VPN flag

| Property | Value |
|---|---|
| Methodology | §6.4 — "наличие транспорта VPN в Transports" / "наличие свойства TRANSPORT_VPN у activeNetwork при проверке hasTransport" |
| What it tests | `ConnectivityManager.getNetworkCapabilities(activeNetwork).hasTransport(TRANSPORT_VPN)` |
| Rule | `true` → HARD, `false` → PASS |
| Methodology axis | direct |
| False positives | Local-VPN ad blockers (AdGuard, Blokada), corporate antivirus packet inspectors, Android per-app firewalls (NetGuard, RethinkDNS) — all of these create a system VPN service and trigger `TRANSPORT_VPN` even though no traffic leaves the device. |
| Mitigations | Combine with `installed_vpn_apps`, `vpn_transport_info` (which exposes the package owning the session), and the methodology decision matrix (one HARD signal alone yields NEEDS_REVIEW, not BYPASS_DETECTED). |
| Limitations | Cannot distinguish VPN-to-foreign-exit from local filtering VPN without inspecting the underlying networks (`underlyingNetworks` is `@SystemApi` — see §6.4 limitations). |

### `cap_not_vpn` — NET_CAPABILITY_NOT_VPN

| Property | Value |
|---|---|
| Methodology | §7.4 — "флаг NOT_VPN в Capabilities. Для обычных сетей этот флаг присутствует, при активном VPN отсутствует" |
| What it tests | `caps.hasCapability(NET_CAPABILITY_NOT_VPN)` |
| Rule | absent → HARD, present → PASS, no active network → INFO |
| Methodology axis | direct |
| False positives | Same as `transport_vpn` (mirror signal). |
| Mitigations | Degraded to INFO when offline / between handoffs. |
| Limitations | Mathematically equivalent to `transport_vpn` for our purposes; kept as a separate row because anti-fraud SDKs check both to defeat naive bypasses. |

### `tun_iface` — tunnel interfaces present

| Property | Value |
|---|---|
| Methodology | §7.4 — "имена интерфейсов tun0, tun1, tap0, wg0, ppp0, ipsec могут указывать на активное VPN-соединение" |
| What it tests | `NetworkInterface.getNetworkInterfaces()` filtered by name prefix `tun/tap/wg/utun/ppp/ipsec` AND `isUp` |
| Rule | any flagged → HARD, none → PASS |
| Methodology axis | direct |
| False positives | Per the methodology: antivirus filters, content filters, corporate security tools, system components. Examples: Bitdefender mobile, Kaspersky, Norton — all create `tun*` for traffic inspection without forwarding off-device. |
| Mitigations | Cross-reference with `installed_vpn_apps` and `dumpsys_vpn` (when available). Listed in the methodology as a *косвенный* (indirect) signal for exactly this reason — we keep it HARD because in our user population the false-positive class is small, but the matrix-axis logic groups it with direct signals so a lone hit alone yields NEEDS_REVIEW not BYPASS_DETECTED. |
| Limitations | Linux-side names only; iOS uses `utun*` (also detected) but per-app VPN profiles can hide. |

### `active_iface_name` — active network interface name

| Property | Value |
|---|---|
| Methodology | §7.4 — same paragraph as `tun_iface`, applied to the *active* default network specifically. |
| What it tests | `LinkProperties.interfaceName` of `activeNetwork` |
| Rule | starts with tunnel prefix → HARD, else PASS |
| Methodology axis | direct |
| False positives | Identical to `tun_iface` but narrowed to the iface that the OS picked as the default route. Slightly stronger signal than enumerating all interfaces. |
| Mitigations | Same as `tun_iface`. |
| Limitations | A split-tunnel VPN that only catches a subset of apps would not necessarily change the active interface for our process. |

### `default_route_tun` — default route via tunnel + WG split-route trick

| Property | Value |
|---|---|
| Methodology | §7.6 — "Маршрут по умолчанию, указывающий на интерфейс, отличный от основного физического или беспроводного" |
| What it tests | `LinkProperties.routes` for any default route with `iface` matching the tunnel prefix list, **plus** the WireGuard `0.0.0.0/1 + 128.0.0.0/1` split-route trick that some clients use to disguise their default route. |
| Rule | either pattern → HARD, else PASS |
| Methodology axis | direct |
| False positives | Same class as `tun_iface`. The WG-trick check is specific enough not to false-positive on legitimate setups. |
| Mitigations | None additional. |
| Limitations | The route table accessible to a regular app on Android only includes the active network — not all routes the kernel knows. Hidden split-tunnel setups may not appear. |

### `http_proxy` — system HTTP proxy on the active link

| Property | Value |
|---|---|
| Methodology | §6.4 — "При выявлении в системных настройках данных об IP и порте Proxy вероятно весь трафик направляется через него" |
| What it tests | `LinkProperties.httpProxy` (PAC URL or host/port) |
| Rule | non-null → HARD, null → PASS |
| Methodology axis | direct |
| False positives | Captive-portal Wi-Fi auth proxies, corporate networks. The methodology lists these in §4. |
| Mitigations | Combine with the locale/SIM-country signal — a corporate proxy on a RU-locale device on a RU SIM is much less suspicious than the same proxy on a non-RU IP. |
| Limitations | Per-process proxies set via `System.getProperty` are not visible here — see `jvm_proxy` below for that case. |

### `jvm_proxy` — JVM proxy properties (NEW v0.4.0)

| Property | Value |
|---|---|
| Methodology | §6.4 — "Для выявления Proxy следует проводить анализ System.getProperty и иных доступных системных настроек" |
| What it tests | `System.getProperty("http.proxyHost" / "http.proxyPort" / "https.proxyHost" / "https.proxyPort" / "socksProxyHost" / "socksProxyPort")` |
| Rule | any host property non-empty → HARD, all empty → PASS |
| Methodology axis | direct |
| False positives | Some testing frameworks and IDE attach handlers set these inadvertently. Rare in production. |
| Mitigations | None additional — if a host property is set, the JVM is genuinely routing through it. |
| Limitations | Only sees JVM-process-level proxies. OS-level transparent proxies (iptables REDIRECT) are invisible to this check. See `transparent_proxy_headers` for that case. |

### `vpn_transport_info` — VpnTransportInfo decoding (NEW v0.4.0, API 31+)

| Property | Value |
|---|---|
| Methodology | §6.4 — "наличие VpnTransportInfo" with example output `VpnTransportInfo{type=1, sessionId=PCAPdroid VPN, bypassable=false, longLiveTcpConnectionsExpensive=false}` |
| What it tests | `caps.transportInfo` on API 31+, decoded as `VpnTransportInfo` |
| Rule | non-null and `simpleName == "VpnTransportInfo"` → HARD, else PASS |
| Methodology axis | direct |
| False positives | A local-VPN ad blocker will produce a non-null `VpnTransportInfo` with a recognisable `sessionId`. The session id surfaces the owning app, which lets a tester whitelist by name. |
| Mitigations | Reading the `sessionId` field directly when possible would let us correlate with `installed_vpn_apps`. Not yet wired through; stored in the row's `value` field as plain text. |
| Limitations | Only API 31+. Pre-Android-12 devices return a null transportInfo. |

### `route_anomalies` — routing-table anomaly counts (NEW v0.4.0)

| Property | Value |
|---|---|
| Methodology | §7.6 — "Наличие выделенных маршрутов, направляющих трафик на нестандартные шлюзы. Использование нестандартных значений MTU. Наличие маршрутов, указывающих на использование split tunneling" |
| What it tests | Counts `LinkProperties.routes` partitioned into: total, isDefaultRoute, via tunnel iface |
| Rule | >1 default routes OR any route via tunnel iface → SOFT, else PASS |
| Methodology axis | indirect |
| False positives | The methodology explicitly warns: "Множественные интерфейсы и виртуальные маршруты создаются WSL2, Hyper-V, VirtualBox, антивирусами, средствами родительского контроля и иными легитимными компонентами." Almost any device with split-DNS or per-app VPN exclusion has multiple defaults. |
| Mitigations | Severity is SOFT, not HARD. Per-source DetailEntry breakdown lets a tester immediately see what the actual counts are without re-deriving. |
| Limitations | Android only exposes the active network's routes, not the full kernel routing table. Less rich than the desktop equivalent. |

### `dumpsys_vpn` — dumpsys vpn_management shell-out (NEW v0.4.0)

| Property | Value |
|---|---|
| Methodology | §7.4 — "Еще одним инструментом для сбора косвенных признаков для ОС Android 12+ могут использоваться сервисные данные вида dumpsys vpn_management" |
| What it tests | `Runtime.exec("/system/bin/dumpsys vpn_management")` and parses lines matching `Active package name:` or `Active vpn package:` |
| Rule | succeeds and finds packages → HARD; succeeds and empty → PASS; fails / permission denied → INFO |
| Methodology axis | direct (when it succeeds) |
| False positives | Same as `installed_vpn_apps` if the user has a local-VPN ad blocker. |
| Mitigations | Treats permission-denied output as INFO (the documented expected case on production builds for a regular uid). |
| Limitations | The methodology's example output assumes `DUMP` permission. On a regular uid on production Android the call returns `Permission Denial: can't dump`. We classify that as INFO and surface "denied (no DUMP permission, expected on production builds)" so a tester knows the row is informational. On userdebug builds and some OEM ROMs the call succeeds and reveals the active VPN package. |

### `private_dns` — Private DNS (DoT)

| Property | Value |
|---|---|
| Methodology | §7.7 — "Анализ настроек DNS также относится к косвенным признакам. Явное изменение DNS-сервера на публичный адрес либо DNS внутри VPN-сети может быть уточняющим признаком" |
| What it tests | `LinkProperties.isPrivateDnsActive` and `privateDnsServerName`, with a known-public-DoT host substring match (Cloudflare, Google, AdGuard, Quad9, NextDNS) |
| Rule | known public DoT → SOFT, active with unknown name → SOFT, off → PASS |
| Methodology axis | indirect |
| False positives | The methodology lists ad-blocker apps and corporate-DoT setups as legitimate sources. |
| Mitigations | SOFT, not HARD. |
| Limitations | Only Android 9+. |

### `dns_servers` — DNS servers list

| Property | Value |
|---|---|
| Methodology | §7.7 — same paragraph |
| What it tests | `LinkProperties.dnsServers` matched against a known-public-resolver list (1.1.1.1, 8.8.8.8, 9.9.9.9, AdGuard, OpenDNS) |
| Rule | any public resolver in the list → SOFT, else PASS |
| Methodology axis | indirect |
| False positives | The methodology spells these out: ad blockers, DoT-on-router, corporate DNS, manual user override. |
| Mitigations | SOFT only. |
| Limitations | Doesn't catch DoH-only resolvers (those don't appear as system DNS servers). Doesn't catch resolver-over-VPN setups (where the DNS server is `192.168.1.1` but `192.168.1.1` itself uses Cloudflare upstream). |

### `always_on_vpn`

| Property | Value |
|---|---|
| Methodology | not directly cited; the methodology mentions Android lockdown VPN as part of §6.4 background. |
| What it tests | `Settings.Secure.always_on_vpn_app` and `always_on_vpn_lockdown` |
| Rule | non-empty → SOFT, else PASS |
| Methodology axis | indirect |
| False positives | Many enterprise MDM setups force always-on VPN for compliance. |
| Mitigations | SOFT only. |
| Limitations | Some OEM ROMs restrict reading these `Settings.Secure` keys without privileged perms. |

### `installed_vpn_apps`

| Property | Value |
|---|---|
| Methodology | §7.8 — "Проверка специализированных утилит, например proxychains или tsocks. Выявление системных процессов proxy-серверов по именам процессов" |
| What it tests | `PackageManager.getPackageInfo` against an extended list (v0.4.0 added ByeDPI, Orbot, Intra, ProxyDroid, AdGuard VPN). |
| Rule | any installed → SOFT, none → PASS |
| Methodology axis | indirect |
| False positives | A power user may have a VPN client installed without using it. The methodology recognises this and lists §7.4 as the place to add `dumpsys` correlation. |
| Mitigations | SOFT. Cross-correlate with `dumpsys_vpn` when that succeeds. |
| Limitations | Only catches packages we know about. Custom in-app VPN clients (some bank's "secure browser") are missed. Requires `QUERY_ALL_PACKAGES`. |

### `mtu` — active iface MTU

| Property | Value |
|---|---|
| Methodology | §7.6 — "Использование нестандартных значений MTU" |
| What it tests | `NetworkInterface.getMTU()` of the active iface |
| Rule | 1280/1380/1420 → SOFT (typical WG/AmneziaWG/v4-tun); <1500 on `wlan*`/`eth*` → SOFT; else PASS |
| Methodology axis | indirect |
| False positives | Cellular networks often advertise MTU < 1500 (per the methodology, this is exactly why MTU is indirect). |
| Mitigations | We only flag SOFT on Wi-Fi/Ethernet, not on `rmnet*`/`ccmni*` cellular interfaces. |
| Limitations | A VPN configured with MTU 1500 is invisible to this check. |

### `mock_location`, `dev_options`, `active_transport`, `wifi_ssid`, `root`

These rows are diagnostic context (`INFO` or `PASS`) used for the methodology's §4 false-positive mitigation strategies (combine with location data, build profile of "normal" device). They do not contribute to the score on their own. See `SystemChecks.kt` for the per-check rules.

### `telegram_present` — weak bypass-behaviour signal

| Property | Value |
|---|---|
| Methodology | not directly in the document; our own addition. The methodology's §4 mentions cross-correlating with "history of past sessions" — Telegram presence is a coarse correlation. |
| What it tests | Eight Telegram-family package names + Usage Access running-state probe |
| Rule | any installed → SOFT, none → PASS |
| Methodology axis | indirect |
| False positives | Many users have Telegram and never use it for anything sensitive. |
| Mitigations | SOFT only. The DetailEntry breakdown lists exactly which packages were found and (when Usage Access is granted) which is currently in the foreground. |
| Limitations | Methodology-adjacent, not directly cited. Could be removed or downgraded to INFO if too noisy. |

---

## GEOIP tab — what the world sees

Methodology §5.4 (GeoIP analysis algorithm) and §10 (supplementary methods).
File: [`detect/geoip/GeoIpProbes.kt`](../../app/src/main/kotlin/net/vpndetector/detect/geoip/GeoIpProbes.kt)

### `probe_*` — raw GeoIP probe rows

INFO rows, one per provider (`ipify`, `ipinfo`, `ip-api`, `ifconfig.co`, `myip.com`, `cf-trace`). They surface the raw answers so the tester can audit each source independently. Methodology §5.3 — "В качестве референсной БД должна выступать система РАНР. До момента ее ввода в эксплуатацию допускается использование альтернативных БД."

### `external_country` — canonical external country

INFO/PASS row with the consensus country across probes. Used by the History axis (`country_history`) and the Consistency tab.

### `asn_class` — ASN classification + CDN whitelist (UPDATED v0.4.0)

| Property | Value |
|---|---|
| Methodology | §5.4 step 3 — "Определить ASN, тип сети и наличие признака hosting" + §4 — CDN whitelisting as false-positive mitigation |
| What it tests | Each probe's `org` field substring-matched against a list of known datacenter keywords; CDN-keyword match overrides datacenter match (whitelist) |
| Rule | per-probe row: CDN match → INFO, datacenter match → HARD, residential → PASS, no org → INFO. Aggregate row: HARD if any per-probe row HARD, else PASS. |
| Methodology axis | geoip |
| False positives | The methodology explicitly warns: "Корпоративный легальные VPN часто в качестве точки терминации имеют дата-центр и по GeoIP могут определяться как средствами обхода блокировок." Same applies to legitimate datacenter-fronted apps. |
| Mitigations | (NEW v0.4.0) CDN whitelist for Cloudflare/Akamai/Fastly/CloudFront/Google/Incapsula/StackPath/BunnyCDN/KeyCDN/Azure CDN/Azure Front Door — datacenter match is overridden if the org also matches a CDN keyword. |
| Limitations | Substring matching is coarse and may miss organizations with unusual names. The methodology recommends using the РАНР registry as the authoritative source — we use public free probes. |

### `reputation_flag` — proxy/hosting/vpn flags from probes

| Property | Value |
|---|---|
| Methodology | §5.4 step 4 — "Проверить адрес по репутационным спискам VPN, proxy и TOR" |
| What it tests | Each probe's `isProxy`/`isHosting`/`isVpn` field; Cloudflare cdn-cgi/trace `warp=on`/`gateway=on` is treated as `isVpn=true` |
| Rule | per-probe row: any true → HARD, all false → PASS, none reported → INFO. Aggregate row: HARD if any per-probe row HARD. |
| Methodology axis | geoip |
| False positives | The methodology warns: "Новые VPN-серверы появляются быстрее, чем обновляются репутационные базы." The opposite also happens — IPs get added to reputation lists and stay there long after they stop hosting VPNs. |
| Mitigations | Per-source DetailEntry breakdown so the tester can see which provider returned which field, and discount stale ones. |
| Limitations | We rely on free providers; ip-api.com is the only one with proxy/hosting flags on the free tier. Paid ipinfo / IPQualityScore would give richer data. |

### `probe_ip_agreement`, `probe_country_agreement`

Detect split-routing and DB lag respectively. Methodology §4 mentions "повторная проверка с задержкой" — these checks are the synchronous equivalent run across multiple providers in parallel.

### `transparent_proxy_headers` — Via / X-Forwarded-For / Forwarded (NEW v0.4.0)

| Property | Value |
|---|---|
| Methodology | §10.2 — "Наличие заголовков X-Forwarded-For, Forwarded или Via может указывать на прохождение через промежуточный proxy-узел" |
| What it tests | Every GeoIP probe response is inspected for `Via`, `X-Forwarded-For`, `Forwarded`, `X-Real-IP` headers. |
| Rule | any header on any probe → HARD, none → PASS |
| Methodology axis | indirect |
| False positives | The methodology cautions: "сам сервис или CDN также может легитимно формировать часть таких заголовков." A probe that itself runs behind a load balancer may inject `X-Forwarded-For` into its response. |
| Mitigations | OkHttp client uses `Proxy.NO_PROXY` so we know no intentional proxy was added on our end. Per-source DetailEntry breakdown lets a tester see which probe and which header. If only one provider sets `Via`, that's noise; if four out of six do, it's a real middlebox. |
| Limitations | Most well-behaved GeoIP services strip these headers from responses, but a few don't. Validation needed before promoting from "implemented" to "trusted". |

### `country_history` — rapid country change between runs (NEW v0.4.0)

| Property | Value |
|---|---|
| Methodology | §5.4 step 5 — "Сопоставить полученные данные с историей прошлых сессий" |
| What it tests | Compares `external_country` of the most-recent prior run against the current run |
| Rule | same country → PASS. Different + <1h gap → HARD (no plausible travel). Different + <12h → SOFT (possible travel). Different + >12h → INFO. |
| Methodology axis | geoip |
| False positives | International travel; switching between Wi-Fi networks in different operator footprints (rare). |
| Mitigations | Severity drops with gap age. Travel >12h is INFO not HARD. |
| Limitations | Depends on having at least one prior run in history. First run produces no `country_history` row. Could be extended to a sliding window across the last N runs. |

---

## CONSISTENCY tab — local context vs external IP

Methodology §5.4 step 6 — "При наличии результатов анализа на клиентской стороне сравнить результаты с GeoIP" — and §4 mitigation #5 ("Комбинирование с другими источниками данных. Использование дополнительных факторов: данные GPS устройства, информация о сотовой вышке").

File: [`detect/consistency/ConsistencyChecks.kt`](../../app/src/main/kotlin/net/vpndetector/detect/consistency/ConsistencyChecks.kt)

This entire tab implements the cross-correlation step. Each row compares a local source of truth against the GeoIP-claimed location:

| Row | Local source | GeoIP source | Severity |
|---|---|---|---|
| `sim_vs_ip` | `TelephonyManager.simCountryIso` | external country | HARD on mismatch |
| `net_vs_ip` | `TelephonyManager.networkCountryIso` | external country | HARD on mismatch |
| `carrier_vs_asn` | `TelephonyManager.networkOperatorName` | ASN org | HARD when RU operator name + non-RU ASN |
| `mcc_vs_ip` | `networkOperator[0..3]` (MCC) | external country | HARD when MCC=250 + IP≠RU |
| `locale_vs_ip` | `Locale.getDefault().country` | external country | SOFT on mismatch |
| `lang_vs_ip` | `Locale.getDefault().language` | external country | SOFT when ru-language + non-CIS IP |
| `tz_vs_ip` | `TimeZone.getDefault().id` | ipinfo `timezone` field | SOFT on mismatch |
| `ru_apps` | `PackageManager` markers (`ru.sberbank*`, `ru.yandex*`, `ru.tinkoff*`, etc.) | external country | SOFT when ≥3 RU apps + non-RU IP |

Methodology axis: `geoip` (these are server-equivalent: they all answer "does the GeoIP-claimed location match the device's other observable facts").

False positives across this tab:

- **International travel.** A RU-locale device temporarily abroad will trip `sim_vs_ip` (when not roaming) and `tz_vs_ip` (when the user manually overrides). Methodology §5.6 explicitly mentions this: "При нахождении пользователя в роуминге точка выхода в интернет может находиться в стране пребывания, что создаст несоответствие GeoIP."
- **Multi-SIM dual-active** devices where one SIM is RU and the other is foreign.
- **Manual locale override** on a vacation phone.

Mitigations: severity gradient (HARD for SIM/network/MCC, SOFT for locale/lang/tz). Combine with the matrix-axis logic — even if the consistency tab fires, BYPASS_DETECTED requires either direct or indirect signals to also fire.

---

## PROBES tab — active network behaviour

File: [`detect/probes/ActiveProbes.kt`](../../app/src/main/kotlin/net/vpndetector/detect/probes/ActiveProbes.kt), [`detect/probes/Traceroute.kt`](../../app/src/main/kotlin/net/vpndetector/detect/probes/Traceroute.kt), [`detect/probes/LocalListenerProbe.kt`](../../app/src/main/kotlin/net/vpndetector/detect/probes/LocalListenerProbe.kt)

### `lat_ru`, `lat_foreign`, `lat_ratio` — latency anchors

| Property | Value |
|---|---|
| Methodology | §10.1 — "Метод анализа задержек SNITCH" — "Server-side Non-intrusive Identification of Tunnelled Characteristics... Аномально высокая задержка для геолокации IP-адреса, указывает на использование VPN" |
| What it tests | Median TTFB to three RU anchors and three foreign anchors, run in parallel. |
| Rule | `lat_ru` >200ms → HARD, 100-200 → SOFT. `lat_foreign` <30ms → HARD, 30-80 → SOFT. `lat_ratio`: foreign faster than RU → HARD. |
| Methodology axis | indirect |
| False positives | Anchor host overload, Wi-Fi congestion, mobile networks with bursty latency. |
| Mitigations | Three anchors per side; median used (not mean) to discard one outlier. Per-host DetailEntry breakdown so a tester can see which specific anchor is misbehaving. |
| Limitations | Threshold-based. The methodology's SNITCH approach uses expected RTT for the GeoIP-claimed location, not fixed thresholds — that's a v0.5+ improvement. |

### `router_egress_country` — traceroute to first non-RFC1918 hop

| Property | Value |
|---|---|
| Methodology | not directly cited; the methodology §8.7 mentions router-side VPN as a documented blind spot ("Методика не рассматривает ситуации, когда VPN разворачивается на пользовательском маршрутизаторе"). This check explicitly closes that gap. |
| What it tests | `Runtime.exec("/system/bin/ping -c 1 -W 1 -n -t N 1.1.1.1")` for N=1..15 in parallel; parses `From X.X.X.X` and `bytes from X.X.X.X`; GeoIP-resolves each unique non-RFC1918 hop. |
| Rule | first non-RFC1918 hop's country differs from SIM country → HARD; matches → PASS; no hops → INFO |
| Methodology axis | indirect |
| False positives | First public hop being in a different country happens with some carrier-level transit topologies (rare on residential ISPs). |
| Mitigations | RFC1918 + CGNAT (`100.64.0.0/10`) hops are skipped. Per-hop DetailEntry breakdown shows the full path. |
| Limitations | Requires SIM country to be known. Some carriers drop ICMP TTL-exceeded entirely; the check then degrades to INFO. |

### `local_proxy_listeners` — TCP-connect to known proxy ports (NEW v0.4.0)

| Property | Value |
|---|---|
| Methodology | §6.4 — proxy port list per technology (SOCKS 1080/9000/9050/9051/9150, HTTP 3128/8080/8888, transparent 4080/7000/7044/12345, Tor 9050/9051/9150) and §7.8 — "Выявление системных процессов proxy-серверов по именам процессов и характерным портам" |
| What it tests | TCP-connects to `127.0.0.1` on every port in the methodology's port list, with a 60ms timeout. Any successful connect proves a proxy is listening on that port on this device. |
| Rule | any open → SOFT, none → PASS |
| Methodology axis | indirect |
| False positives | Some legitimate apps run debug servers on these ports — Android Studio's emulator runs an ADB proxy on `5555` (we include this port in the list because the methodology cites it). |
| Mitigations | Per-port DetailEntry breakdown labels each open port with its likely technology so a tester can investigate. Severity is SOFT not HARD. |
| Limitations | Bypasses Android-10+ SELinux block on `/proc/net/tcp` enumeration. SELinux is the reason this check exists in this form: a regular app cannot read other-uid sockets directly, so we probe by attempting to connect. The methodology assumes server-side or root access — our workaround approximates the same signal from an unprivileged uid. |

### `ipv6`, `local_addrs`, `captive_portal`

INFO context rows. Used as supporting evidence in the methodology decision matrix when other axes are ambiguous.

---

## Methodology decision matrix (NEW v0.4.0)

Methodology §9 Table 2 defines a 3-axis × 3-class decision matrix. The implementation in `Verdict.kt`:

- **GeoIP axis fires** when any HARD signal is in the GeoIP set (`asn_class`, `reputation_flag`, `probe_ip_agreement`, `probe_country_agreement`, `country_history`, plus the consistency cross-checks).
- **Direct axis fires** when any HARD signal is in the direct set (`transport_vpn`, `cap_not_vpn`, `tun_iface`, `active_iface_name`, `default_route_tun`, `http_proxy`, `jvm_proxy`, `vpn_transport_info`, `dumpsys_vpn`, `local_proxy_listeners`).
- **Indirect axis fires** when any HARD signal is in the indirect set (`private_dns`, `dns_servers`, `mtu`, `route_anomalies`, `always_on_vpn`, `installed_vpn_apps`, `telegram_present`, `root`, `mock_location`, `lat_ru`, `lat_foreign`, `lat_ratio`, `router_egress_country`, `transparent_proxy_headers`).

Decision rule (derived from the methodology table):

| Axes fired | Label |
|---|---|
| 0 | `BYPASS_NOT_DETECTED` |
| 1 (geoip alone) | `NEEDS_REVIEW` (server says VPN, client says clean) |
| 1 (direct or indirect alone) | `BYPASS_NOT_DETECTED` (single-axis hits are not enough) |
| 2 or 3 | `BYPASS_DETECTED` |

This runs alongside the existing scalar verdict (`CLEAN` / `SUSPICIOUS` / `DETECTED`) and is shown on the verdict bar, in the share text, and in the logcat dump. The two verdicts are not redundant: the scalar one captures *intensity* (how much evidence accumulated), the matrix one captures *agreement* (whether multiple categories of evidence concur).

---

## Known gaps vs the methodology (still open)

These are documented and tracked, not yet implemented:

1. **iOS support** (methodology §6.5, §7.5) — out of scope for this Android-only project.
2. **Authoritative DNS leak test** (methodology §7.7 last bullet) — requires hosting a controlled domain. Deferred until we register one.
3. **TLS MITM cert pinning** (methodology §7.8 last bullet) — would detect corporate / antivirus / state-level TLS interception. Doable but adds a hard dependency on a stable cert anchor.
4. **Magisk Hide / Zygisk detection** (related to §7.4 root signal) — limited from a non-root app; current implementation is heuristic file-existence only.
5. **Per-app split-tunnel detection** (methodology §7.9 explicitly cites this as a limitation) — hard on Android because all our HTTP goes through our own process. Not pursued.
6. **SNITCH expected-RTT lookup table** (methodology §10.1 in its full form) — currently we use fixed thresholds, not coordinate-based expected RTT. Tier 3 enhancement.
7. **Desktop / UNIX / Windows / macOS support** (methodology §8) — explicitly deferred per the methodology's own staging recommendation.
8. **Whitelist of known corporate VPN ranges** (methodology §4 mitigation #1) — would need a maintained data file. Not yet built.

---

## Limitations and disclaimers

This is a QA harness, not a production anti-fraud SDK. Differences from a real production SDK:

- **No telemetry, no backend.** Every signal is computed locally and shown in the UI; nothing is reported anywhere. The methodology assumes a server side that aggregates many devices over time (§5.1, §9). We do not.
- **Public free GeoIP probes.** Production SDKs would use the РАНР registry (§5.3) or paid commercial sources. We use public free providers, which means we inherit their staleness and rate limits.
- **Single-snapshot run.** The methodology recommends history correlation (§4, §5.4 step 5). We have a primitive `country_history` cross-run check; deeper temporal analysis is out of scope.
- **No "повторная проверка с задержкой"** (§4 mitigation #4 — repeat the check after a delay to filter transient anomalies) — the user can manually re-tap the FAB but there is no automatic re-check.

These are intentional, not bugs. The point of the harness is to make every individual signal observable and auditable on the user's own device.
