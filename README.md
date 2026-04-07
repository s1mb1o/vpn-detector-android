# vpn-detector-android

Diagnostic Android app that mirrors how Russian banking / anti-fraud / RKN-aligned SDKs detect a VPN on a user's device. Built as a feedback oracle for tuning the MikroTik-based home VPN setup in [`~/Projects/10_admin/mikrotik`](../../10_admin/mikrotik) — every router change can be re-tested by tapping **Run all checks** and comparing history entries.

This is **not** a product. No store release, no analytics, no telemetry. Sideload only.

## What it checks

Four categories, exhaustive catalog in [`docs/SIGNAL_CATALOG.md`](docs/SIGNAL_CATALOG.md) (mirrors the plan):

- **System** — `TRANSPORT_VPN`, `tun*`/`wg*` interfaces, default route via tunnel, `underlyingNetworks`, HTTP proxy, Private DNS, DNS servers, MTU, always-on VPN, installed VPN apps, root indicators.
- **GeoIP** — parallel probes against ipify, ipinfo, ip-api, ifconfig.co, myip.com, Cloudflare trace; ASN classification, reputation flags, probe disagreement.
- **Consistency** — SIM country / network country / carrier / MCC / locale / language / timezone vs external GeoIP. **The decisive tab for our setup.**
- **Probes** — latency to RU vs foreign anchors, IPv6 reachability, captive portal, local addresses.

Each check shows raw value, severity (PASS / INFO / WARN / FAIL) and one-line explanation. Verdict bar aggregates: HARD fail = `DETECTED`, soft fails = `SUSPICIOUS`.

## Build

```bash
cd ~/Projects/40_pet/vpn-detector-android
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n ru.shmelev.vpndetector/.MainActivity
```

Requirements: Android Studio Ladybug+ / JDK 17 / Android SDK 35. Min device: Android 8.

## Smoke tests

See [`SMOKE_TESTS.md`](SMOKE_TESTS.md) — manual scenarios to run on the phone after each MikroTik change.

## Related

- Plan: `~/.claude/plans/misty-doodling-candle.md`
- Threat model & RKN research: `~/Projects/10_admin/mikrotik/docs/rkn/`
