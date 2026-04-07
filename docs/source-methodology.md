# Source methodology

This project implements the on-device VPN-detection methodology described in publicly available Russian-language anti-fraud research, so that compliance engineers and security testers can validate their detection logic against the same signal set on a controlled test device.

## Primary reference

> *"Методика выявления VPN на пользовательских устройствах: технический разбор и слабые места"* (Methodology for VPN Detection on User Devices: Technical Analysis and Weak Points)
>
> Author: ГигаНяшка · Published: securitylab.ru, April 2026 · [link](https://www.securitylab.ru/blog/personal/Techno_Obzor/360239.php)

The article is a third-party technical breakdown of the four-stage methodology that anti-fraud SDKs in Russian banking, госуслуги, and marketplace apps use to flag a device as "running a VPN". It also discusses the methodology's blind spots and false-positive triggers.

## Methodology stages and how the app maps to them

The article describes the methodology as a four-stage pipeline. Each stage maps directly onto one of the app's four detection categories:

| Stage in the methodology | App category | Implementation |
|---|---|---|
| 1. Server-side GeoIP analysis | **GeoIP** tab | `detect/geoip/GeoIpProbes.kt` — six parallel public probes; ASN classification; reputation flag aggregation; probe disagreement |
| 2. Direct mobile-device VPN indicators | **System** tab | `detect/system/SystemChecks.kt` — `TRANSPORT_VPN`, `tun*` interface enumeration, default-route-via-tunnel detection, HTTP proxy, Private DNS |
| 3. Indirect system signatures | **System** + **Consistency** tabs | DNS resolver class, MTU, installed VPN packages, root indicators, Telegram presence; SIM-vs-IP / locale-vs-IP / timezone-vs-IP cross-checks |
| 4. Cross-platform / behavioral coverage | **Active probes** tab | `detect/probes/ActiveProbes.kt` — RU vs foreign latency anchors, IPv6 reachability, captive portal probe |

Every individual rule is documented in [`01_signal-catalog.md`](specs/01_signal-catalog.md) with its FAIL / WARN / PASS conditions, and the scoring rules are in [`03_scoring.md`](specs/03_scoring.md).

## Acknowledged blind spots (per the source)

The methodology, by the article's own analysis, cannot detect:

- VPN configured on the **router** (the device itself sees no VPN)
- **Residential proxies** on legitimate home-ISP IPs
- VPN infrastructure deployed faster than reputation databases update

These are the same blind spots a QA tester needs to be aware of when interpreting a CLEAN verdict on a real test device — a CLEAN result does not prove the test device is not behind a VPN, only that none of the documented client-side signals are visible.

## Documented false-positive triggers (per the source)

The article notes the following legitimate configurations that fire the methodology's flags:

- Custom DNS resolvers (DoT / DoH to public providers)
- Local-VPN-interface ad blockers
- Corporate antivirus solutions with on-device packet inspection
- Development environments running Docker / WSL2 networking shims

The app surfaces all of these as SOFT signals so that a tester can see which false-positive class their device falls into, rather than getting an opaque "DETECTED" verdict.

## Why a separate test harness exists

Anti-fraud SDKs are usually shipped as obfuscated binary blobs inside production apps. A compliance engineer who wants to know "what does my customer's device actually look like to the SDK" cannot easily extract that signal from the SDK itself. This harness reproduces the documented methodology in plain Kotlin source so that the inputs, the rules, and the verdict are auditable and reproducible.

## Out of scope

- Implementing or distributing any circumvention tool
- Bypassing, obfuscating, or otherwise defeating the methodology
- Forwarding device data to any backend
