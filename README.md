# VPN Detection QA Harness

A compliance-testing tool for Android. It implements the on-device VPN-detection methodology described in publicly available Russian-language anti-fraud research and reports, on the user's own device, exactly the signals an anti-fraud SDK in a banking / госуслуги / marketplace app would use to flag the device as "running a VPN".

The intended audience is **anti-fraud engineers, security testers, and compliance QA**: people who need to verify that their VPN-detection logic actually triggers on a known-good test device, that their false-positive rate is acceptable, and that a real customer device looks the way they think it looks. Run the app on a clean phone, on a phone behind a corporate proxy, on a phone with a VPN client active — record the verdicts, compare. The output is a structured per-signal breakdown that maps directly to the standard methodology.

## Methodology source

The signal catalog implemented here mirrors the methodology described in:

> *"Методика выявления VPN на пользовательских устройствах: технический разбор и слабые места"* — securitylab.ru, April 2026

A summary, citation, and the catalog mapping are in [`docs/source-methodology.md`](docs/source-methodology.md). Every check in the app is traceable to a section in that methodology.

## What it checks

Four categories, full catalog in [`docs/specs/01_signal-catalog.md`](docs/specs/01_signal-catalog.md):

- **System** — `TRANSPORT_VPN`, `tun*`/`wg*` interfaces, default route via tunnel, HTTP proxy, Private DNS, MTU, installed VPN clients, root indicators, Telegram presence.
- **GeoIP** — six parallel probes (ipify, ipinfo, ip-api, ifconfig.co, myip.com, Cloudflare cdn-cgi/trace); datacenter ASN classification; reputation flags; probe disagreement.
- **Consistency** — cross-checks SIM country / network country / MCC / carrier name / locale / timezone against the external IP. The decisive category for the methodology.
- **Active probes** — RU vs foreign latency anchors, IPv6 reachability, captive portal.

Each row reports raw value, severity (PASS / INFO / WARN / FAIL) and a one-line explanation. Tap a row to see the per-source breakdown — for each multi-source check, the dialog lists exactly which probe / anchor / package returned what, so a tester can isolate which specific input drove the verdict.

The verdict bar aggregates: HARD failure → DETECTED, three+ soft hits → SUSPICIOUS, otherwise CLEAN. Scoring rules in [`docs/specs/03_scoring.md`](docs/specs/03_scoring.md).

## Build

```bash
cd ~/Projects/40_pet/vpn-detector-android
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Requirements: Android Studio Ladybug+ / JDK 17 or 21 / Android SDK 35. Min device: Android 8.

A signed release APK is produced by `./gradlew :app:assembleRelease` (requires `keystore.properties` — see the comment in `app/build.gradle.kts`).

## Smoke tests

[`SMOKE_TESTS.md`](SMOKE_TESTS.md) — manual scenarios to run on a test device after each tweak to the detection rules.

## Documentation

The project ships with two parallel documentation trees:

- [`docs/specs/`](docs/specs/) — formal specifications of every detection rule implemented in the app:
  - [`01_signal-catalog.md`](docs/specs/01_signal-catalog.md) — every Check, FAIL/WARN/PASS conditions
  - [`02_architecture.md`](docs/specs/02_architecture.md) — engine + UI + data flow
  - [`03_scoring.md`](docs/specs/03_scoring.md) — VerdictAggregator weights and thresholds
  - [`04_proposed-checks.md`](docs/specs/04_proposed-checks.md) — bypass-direction checks (DNS, blocked-domain, traceroute)
  - [`05_metrics-review.md`](docs/specs/05_metrics-review.md) — per-check audit, methodology mapping, false positives
  - [`06_hiding-strategies.md`](docs/specs/06_hiding-strategies.md) — operator-side advice on lowering the score
- [`docs/knowledge-base/`](docs/knowledge-base/) — research and operator know-how derived from real-device testing:
  - [`README.md`](docs/knowledge-base/README.md) — index and reading order
  - [`threat-model.md`](docs/knowledge-base/threat-model.md) — what we defend against, why
  - [`adr-001-whitelist-routing.md`](docs/knowledge-base/adr-001-whitelist-routing.md) — architecture decision: invert MikroTik routing default
  - [`router-blueprint.md`](docs/knowledge-base/router-blueprint.md) — actual L3 topology of the home MikroTik with real traceroute data
  - [`operator-playbook.md`](docs/knowledge-base/operator-playbook.md) — pragmatic step-by-step recipes per operating mode

Plus: [`docs/source-methodology.md`](docs/source-methodology.md) cites the published methodology this project mirrors, and [`ResearchLog.md`](ResearchLog.md) records ad-hoc API research and on-device validation runs.

## Privacy

The app contains no analytics, no telemetry, no third-party tracking SDKs. The only outbound traffic is the diagnostic probes themselves; full inventory in [`PRIVACY.md`](PRIVACY.md).

## Related (external to this repo)

- Plan: `~/.claude/plans/misty-doodling-candle.md`
- Methodology research notes (authoritative copy): `~/Projects/10_admin/mikrotik/docs/rkn/`
- MikroTik configs and ChangeLog: `~/Projects/10_admin/mikrotik/`
