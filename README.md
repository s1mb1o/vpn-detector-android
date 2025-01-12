# VPN Detector for Android

A research and diagnostic Android app that detects active VPN connections on the device using the same signals that anti-fraud SDKs rely on.

## Motivation

Mobile anti-fraud SDKs in banking, e-commerce, and identity-verification apps silently fingerprint devices for VPN usage. The detection signals they use are undocumented and scattered across Android APIs. This project collects and implements those signals in a single open-source app, so that:

- **Security researchers** can study what data anti-fraud SDKs actually harvest
- **Privacy-conscious users** can see exactly what their device reveals about VPN usage
- **QA engineers** can verify that their VPN-detection logic triggers correctly on test devices

## What it checks

Currently implemented:

- **System** — `TRANSPORT_VPN`, `NOT_VPN` capability, tunnel interfaces, active interface, default route, HTTP proxy, Private DNS, DNS servers, MTU, installed VPN apps, mock location, developer options, root indicators
- **GeoIP** — six parallel probes (ipify, ipinfo, ip-api, ifconfig.co, myip.com, Cloudflare cdn-cgi/trace)

Each check reports a severity: HARD (single-handed detection), SOFT (contributes to score), INFO (diagnostic), PASS (clean). The verdict bar shows: score >= 100 → DETECTED, >= 30 → SUSPICIOUS, else CLEAN.

See [ROADMAP.md](ROADMAP.md) for planned features.

## Build

```bash
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Requirements: Android Studio / JDK 17 / Android SDK 35. Min device: Android 8 (API 26).

## License

MIT
