# Architecture

Single-module Android app. Diagnostic tool — no telemetry, no persistence beyond local DataStore history.

## Layers

```
ui/                  ← Compose UI, fully data-driven from Check records
 ├ App.kt            ← NavHost + bottom nav + verdict bar + FAB
 ├ AppViewModel      ← StateFlow<RunResult?>, runAll(tag)
 ├ verdict/          ← VerdictBar (top, persistent)
 ├ tabs/             ← CategoryTab — generic renderer for any Category
 └ history/          ← HistoryScreen

detect/              ← pure logic, no Android Compose deps
 ├ Check.kt          ← data class + Severity + Category enums
 ├ Verdict.kt        ← VerdictAggregator (HARD=100, SOFT=10)
 ├ DetectorEngine    ← orchestrates 4 categories in parallel via coroutineScope/async
 ├ system/           ← SystemChecks — passive on-device signals
 ├ geoip/            ← GeoIpProbes — 6 parallel HTTP probes + derive()
 ├ consistency/      ← ConsistencyChecks — cross-checks local vs GeoIP
 └ probes/           ← ActiveProbes — latency anchors, IPv6, captive portal

data/                ← persistence
 ├ RunRepository     ← DataStore-Preferences, last 50 runs as JSON list
 └ model/RunResult   ← Serializable wrapper (timestamp, tag, checks, verdict)

net/
 ├ HttpClient        ← OkHttp factory: Proxy.NO_PROXY (no double proxy), 4s timeouts
 └ Json              ← kotlinx.serialization Json with ignoreUnknownKeys
```

## Data flow

```
                          ┌─ SystemChecks (sync)
DetectorEngine.runAll() ─┼─ GeoIpProbes (suspend, IO) ──┐
                          ├─ ActiveProbes (suspend, IO) │
                          └─ ConsistencyChecks (sync,   │
                             needs GeoIP results) ◀─────┘
                                       │
                                       ▼
                              List<Check> (~40 rows)
                                       │
                                       ▼
                          VerdictAggregator.aggregate()
                                       │
                                       ▼
                                 RunResult
                          ┌────────────┴────────────┐
                          ▼                         ▼
                    StateFlow → UI            RunRepository (DataStore)
```

## Threading

- `DetectorEngine.runAll` runs on `Dispatchers.IO`.
- `SystemChecks` is synchronous (microseconds).
- `GeoIpProbes.runAll` and `ActiveProbes.run` use `coroutineScope { async { } }` to fire all HTTP calls in parallel. Total wall time = max(slowest probe, ~4 s timeout).
- `ConsistencyChecks` runs after probes finish since it depends on `ProbeResult.country`.

## Permissions

| Permission | Used by | Degradation if denied |
|---|---|---|
| `INTERNET` | All probes | App is useless |
| `ACCESS_NETWORK_STATE` | SystemChecks (caps, link properties) | All System checks degraded |
| `ACCESS_WIFI_STATE` | wifi_ssid | wifi_ssid = n/a |
| `READ_PHONE_STATE` | sim_vs_ip, net_vs_ip, mcc_vs_ip, carrier_vs_asn | Consistency checks return INFO row "no_phone_perm" |
| `ACCESS_FINE_LOCATION` | wifi_ssid (Android 10+ requires it for SSID) | SSID hidden |
| `QUERY_ALL_PACKAGES` | installed_vpn_apps, ru_apps | Empty results |

## Extension points

- **New check**: add a function returning `Check(...)` in the matching `*Checks.kt`. Update `docs/specs/01_signal-catalog.md`.
- **New GeoIP provider**: add a private `fun providerX(): ProbeResult` in `GeoIpProbes` and append to `runAll()`'s async list.
- **New tab**: add to `Category` enum and to `TABS` list in `App.kt`. `CategoryTab` already filters generically.
- **Tag a run**: `vm.runAll("AWG, split-route on")` — currently only via code, UI input field is TODO.

## Non-goals (v1)

- iOS port
- Play Store release
- Background scheduled runs
- Authoritative-DNS leak test (requires owned domain)
- App icon / branding
