# Signal Catalog — what each check means

This is the source-of-truth specification for every detection rule encoded in the app. Each `Check` returned by the engine corresponds to one row here. UI is fully data-driven from this catalog.

## Severity model

| Level | Meaning | UI |
|---|---|---|
| **HARD** | Single occurrence is enough for an anti-fraud SDK to mark "VPN detected with high confidence". | red `FAIL` |
| **SOFT** | Contributes to a score; multiple soft hits = detection. | orange `WARN` |
| **INFO** | Neutral diagnostic; never affects the verdict. | grey `INFO` |
| **PASS** | Observed value matches a clean RU resident profile. | green `PASS` |

Verdict aggregation: `score = 100*HARD + 10*SOFT`. `DETECTED` ≥100, `SUSPICIOUS` ≥30, else `CLEAN`.

---

## Tab 1 — System (on-device, no network)

Source: `detect/system/SystemChecks.kt`. All values from `ConnectivityManager`, `LinkProperties`, `NetworkCapabilities`, `NetworkInterface`, `Settings.Secure`, `PackageManager`.

| ID | Signal | FAIL when | WARN when | PASS when | Severity |
|---|---|---|---|---|---|
| `transport_vpn` | `hasTransport(TRANSPORT_VPN)` on active network | `true` | — | `false` | HARD |
| `cap_not_vpn` | `hasCapability(NET_CAPABILITY_NOT_VPN)` | absent | — | present | HARD |
| `tun_iface` | Any UP `tun*`/`tap*`/`wg*`/`utun*`/`ppp*` interface | exists | — | none | HARD |
| `active_iface_name` | `LinkProperties.interfaceName` | starts with tun/tap/wg/utun/ppp | — | wlan/rmnet/ccmni/eth | HARD |
| `underlying_networks` | `NetworkCapabilities.underlyingNetworks` (API 31+) | non-empty | — | empty/null | HARD |
| `default_route_tun` | `0.0.0.0/0` via tun OR `0.0.0.0/1`+`128.0.0.0/1` (WG split-route trick) | yes | — | no | HARD |
| `http_proxy` | `LinkProperties.httpProxy` | non-null | — | null | HARD |
| `private_dns` | `isPrivateDnsActive` + DoT hostname match | known public DoT (Google/Cloudflare/AdGuard/Quad9/NextDNS) | active, unknown | off / operator | SOFT |
| `dns_servers` | `LinkProperties.dnsServers` | contains 1.1.1.1, 8.8.8.8, 9.9.9.9, AdGuard, OpenDNS | non-RU non-VPN | RU operator / RFC1918 | SOFT |
| `always_on_vpn` | `Settings.Secure.always_on_vpn_app` + lockdown | non-empty | — | empty | SOFT |
| `installed_vpn_apps` | Known VPN client packages installed | any of 12 listed | — | none | SOFT |
| `mtu` | `NetworkInterface.getMTU()` of active iface | 1280 / 1380 / 1420 (WG/AWG/v4-tun signatures) | <1500 on Wi-Fi | 1500 | SOFT |
| `mock_location` | `Settings.Secure.ALLOW_MOCK_LOCATION` | enabled | — | disabled | SOFT |
| `root` | `/system/.../su` exists OR Magisk package | rooted | — | stock | SOFT |
| `dev_options` | `DEVELOPMENT_SETTINGS_ENABLED` + `ADB_ENABLED` | — | — | — | INFO |
| `active_transport` | WIFI / CELLULAR / ETHERNET | — | — | — | INFO |
| `wifi_ssid` | `WifiManager.connectionInfo.ssid` | — | — | — | INFO |

## Tab 2 — GeoIP (network probes)

Source: `detect/geoip/GeoIpProbes.kt`. Parallel probes; raw rows + derived rows.

### Per-probe rows (always INFO)
- `probe_*` rows are emitted for every provider in `GeoIpProbes.runAll()`, including the core HTTP-exit probes plus the specialty probes used for IPv6 and DNS-resolver egress.

### Derived rows
| ID | Signal | FAIL when | PASS when | Severity |
|---|---|---|---|---|
| `external_country` | Canonical country across probes | non-RU (only INFO; real verdict in Consistency) | RU | INFO/PASS |
| `asn_class` | Substring match against datacenter org keywords (DigitalOcean/AWS/Hetzner/OVH/Linode/Vultr/GCP/Azure/M247/Quadranet/Leaseweb/Cloudflare/DataCamp/Contabo/Scaleway) | datacenter match | residential ISP | HARD |
| `reputation_flag` | Any probe returns `proxy/hosting/vpn=true` | flagged | clean | HARD |
| `probe_ip_agreement` | Distinct external IPs across probes | >1 IP | 1 IP | HARD |
| `probe_country_agreement` | Distinct countries with same IP (DB lag) | >1 country | 1 country | SOFT |

## Tab 3 — Consistency (decisive tab)

Source: `detect/consistency/ConsistencyChecks.kt`. Cross-checks local context against external GeoIP.

| ID | Source A | Source B | FAIL when | Severity |
|---|---|---|---|---|
| `sim_vs_ip` | `TelephonyManager.simCountryIso` | GeoIP country | mismatch | HARD |
| `net_vs_ip` | `TelephonyManager.networkCountryIso` | GeoIP country | mismatch | HARD |
| `carrier_vs_asn` | `networkOperatorName` | GeoIP org | RU carrier name + non-RU/non-RU-ISP ASN | HARD |
| `mcc_vs_ip` | `networkOperator[0..3]` | GeoIP country | MCC=250 + IP≠RU | HARD |
| `locale_vs_ip` | `Locale.getDefault().country` | GeoIP country | mismatch | SOFT |
| `lang_vs_ip` | `Locale.getDefault().language` | GeoIP country | `ru` lang + IP outside CIS | SOFT |
| `tz_vs_ip` | `TimeZone.getDefault().id` | ipinfo timezone | mismatch | SOFT |
| `tz_offset` | device UTC offset | — | — | INFO |
| `ru_apps` | `PackageManager` markers (`ru.sberbank*`, `ru.yandex*`, `ru.tinkoff*`, `vk*`, `gosuslugi*`, `alfabank*`) | GeoIP country | ≥3 RU apps + IP≠RU | SOFT |

## Tab 4 — Probes (active network behavior)

Source: `detect/probes/ActiveProbes.kt`, `Traceroute.kt`, `StunProbe.kt`, `LocalListenerProbe.kt`.

| ID | Method | FAIL when | WARN when | PASS when | Severity |
|---|---|---|---|---|---|
| `lat_ru` | Median HEAD latency to yandex.ru / mail.ru / gosuslugi.ru | — | >400 ms | ≤400 ms | SOFT |
| `lat_foreign` | Median HEAD latency to google / cloudflare / apple | — | <20 ms | ≥20 ms | SOFT |
| `lat_ratio` | Ordering: RU faster than foreign? | — | foreign faster (diagnostic only) | RU faster | INFO/PASS |
| `ipv6` | `https://api6.ipify.org` reachability | — | — | — | INFO |
| `local_addrs` | All non-loopback `NetworkInterface` addresses | — | — | — | INFO |
| `captive_portal` | `connectivitycheck.gstatic.com/generate_204` | non-204 | — | 204 | SOFT |
| `stun_mapped_vs_exit` | STUN UDP mapped address vs HTTP exit | mismatch | — | match | HARD |
| `router_egress_country` | Multi-target traceroute to Cloudflare / Google / Yandex DNS | any target's first public hop country differs from SIM country | — | all resolvable targets match SIM country | HARD/PASS |
| `local_proxy_listeners` | TCP-connect to loopback proxy ports | — | any listener open | none open | SOFT/PASS |

## Adding a new rule

1. Add a function in the appropriate `*Checks.kt` / `*Probes.kt` returning `Check(id, category, label, value, severity, explanation)`.
2. Update this catalog with the same ID and FAIL/WARN/PASS conditions.
3. UI picks it up automatically (each tab filters all checks by category).
