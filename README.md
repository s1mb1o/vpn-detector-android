# VPN Detector for Android

A research and diagnostic Android app that detects active VPN connections on the device using the same signals that anti-fraud SDKs rely on.

## Motivation

Mobile anti-fraud SDKs in banking, e-commerce, and identity-verification apps silently fingerprint devices for VPN usage. The detection signals they use are undocumented and scattered across Android APIs. This project collects and implements those signals in a single open-source app, so that:

- **Security researchers** can study what data anti-fraud SDKs actually harvest
- **Privacy-conscious users** can see exactly what their device reveals about VPN usage
- **QA engineers** can verify that their VPN-detection logic triggers correctly on test devices

## What it checks

Four categories:

- **System** — `TRANSPORT_VPN`, `NOT_VPN` capability, tunnel interfaces, active interface, default route, HTTP proxy, Private DNS, DNS servers, always-on VPN, installed VPN apps, obfuscation toolchain detection, MTU, mock location, developer options, root indicators, JVM proxy, VpnTransportInfo, routing anomalies, dumpsys vpn_management, Telegram presence (CIS)
- **GeoIP** — six parallel probes (ipify, ipinfo, ip-api, ifconfig.co, myip.com, Cloudflare cdn-cgi/trace); datacenter ASN classification with CDN whitelist; reputation flags; probe agreement; transparent proxy headers; country history tracking
- **Consistency** — cross-checks SIM country / network country / MCC / carrier name / locale / language / timezone against the external IP; CIS carrier matching; regional app fingerprinting
- **Active probes** — global latency measurement, IPv6 reachability, local address enumeration, captive portal detection, local proxy listener scanning (19 ports), router egress traceroute

Each check reports a severity: HARD (single-handed detection), SOFT (contributes to score), INFO (diagnostic), PASS (clean). The verdict bar shows: score >= 100 → DETECTED, >= 30 → SUSPICIOUS, else CLEAN.

A three-axis decision matrix (GeoIP / Direct / Indirect) provides an additional structured classification: BYPASS_NOT_DETECTED / NEEDS_REVIEW / BYPASS_DETECTED.

## Build

```bash
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Requirements: Android Studio / JDK 17 / Android SDK 35. Min device: Android 8 (API 26).

A signed release APK is produced by `./gradlew :app:assembleRelease` (requires `keystore.properties` — see the comment in `app/build.gradle.kts`).

## Privacy

No analytics, no telemetry, no third-party tracking SDKs. The only outbound traffic is the diagnostic probes themselves. Full inventory in [PRIVACY.md](PRIVACY.md).

## License

MIT
