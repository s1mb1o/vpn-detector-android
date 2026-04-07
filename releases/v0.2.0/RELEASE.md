# Release notes — v0.2.0

VPN Detection QA harness for Android. Implements the standard Russian-language anti-fraud methodology for client-side VPN detection (see [`docs/source-methodology.md`](docs/source-methodology.md)) so anti-fraud engineers, security testers, and compliance QA can validate that their detection logic actually triggers on a known-good test device. No telemetry, no analytics, no backend.

## Artifact

- File: `app/build/outputs/apk/release/app-release.apk`
- Size: 1.3 MB
- Package: `net.vpndetector`
- App label: **VPN Detection QA**
- Version: 0.2.0
- minSdk 26 (Android 8) · targetSdk 35 (Android 15)

## How to install

1. On the receiving phone: Settings → Security → **Install unknown apps** → enable for the file manager / messenger you'll receive the APK from.
2. Open the APK, accept the install prompt.
3. First launch: grant **Location** when prompted (only used to read Wi-Fi SSID; no GPS).
4. Optional: Settings → Apps → Special access → **Usage access** → enable for VPN Detector. Without this the Telegram-running detection cannot work; everything else still works.

## Verifying the build

Run on the APK before installing if you don't trust the source:

```bash
sha256sum app-release.apk
# expected: 7ee8c08ad6fc7473f18f92ba284e44ba43761e07a630948be0ec62401503f9dc

apksigner verify --print-certs app-release.apk
# expected signer:
#   CN=vpn-detector-anon, OU=diagnostic, O=anonymous, C=ZZ
#   sha256: 01017b111ebb7e9be2cc6768a97e6a38583b0cfb9e198684ffa7ea3c49190d51
```

## What it does

Tap **Run all checks** in the bottom-right. The app runs four categories of checks in parallel and gives a single verdict: **CLEAN / SUSPICIOUS / DETECTED**.

- **System** — local-only signals (`TRANSPORT_VPN`, tun/wg interfaces, default route via tunnel, HTTP proxy, DNS, MTU, installed VPN clients, root, Telegram presence)
- **GeoIP** — 6 parallel probes against ipify, ipinfo, ip-api, ifconfig.co, myip.com, Cloudflare; detects datacenter ASNs and reputation flags
- **Consistency** — cross-checks SIM country / network country / MCC / locale / timezone against the external IP. **The decisive tab.**
- **Probes** — RU vs foreign latency anchors, IPv6 reachability, captive portal

Tap any row to see the source-by-source breakdown (which probe returned what). Use the **Share** icon in the verdict bar to export the run as a markdown report.

## Privacy

See [PRIVACY.md](PRIVACY.md). The app talks to ~12 public network-info services per run (yandex, mail.ru, vk, google, cloudflare, wikipedia, ipify, ipinfo, ip-api, ifconfig.co, myip.com, gstatic). No analytics, no Firebase, no advertising id, no persistent identifier, nothing runs in the background. All run history stays in the app sandbox; backup is disabled.

## Known limitations

- App icon is the system default placeholder.
- Telegram-running detection requires manual Usage Access grant.
- The "DNS leak test" row is informational only — a true authoritative-DNS leak test needs a controlled domain.
- No iOS port.
