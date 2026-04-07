# ChangeLog

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
