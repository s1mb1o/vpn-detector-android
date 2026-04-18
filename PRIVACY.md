# Privacy

`vpn-detector-android` is a personal diagnostic tool. It is not a product, has no telemetry, and is not connected to any backend.

## What stays on the device

- All run history is stored in the app's private DataStore file. It never leaves the phone.
- `android:allowBackup="false"` — Android won't auto-back-up run history to Google Drive.
- Logs (`Log.e`) are logcat-only.
- No Firebase / Crashlytics / Sentry / Google Analytics / advertising ID / install referrer / any analytics SDK is included. The full dependency list is in `gradle/libs.versions.toml`.

## What leaves the device, and to whom

Tapping **Run all checks** sends the diagnostic probes themselves. That
includes regular HTTP requests, DNS resolution, UDP STUN, and
`/system/bin/ping` for traceroute. Your exit IP **is** the measurement.
There is no analytics or backend beyond those probes.

| Endpoint | Purpose |
|---|---|
| `api.ipify.org`, `api6.ipify.org` | external IPv4 / IPv6 |
| `ipinfo.io` | IP + ASN + city |
| `ip-api.com` | IP + ASN + proxy/hosting flags |
| `ifconfig.co` | IP + ASN + timezone |
| `api.myip.com` | IP + country |
| `www.cloudflare.com/cdn-cgi/trace` | Cloudflare WARP detection |
| `ipv4-internet.yandex.net`, `ipv6-internet.yandex.net` | additional external IP endpoints |
| `ifconfig.me`, `checkip.amazonaws.com`, `ip.mail.ru` | additional external IP endpoints |
| `whoami.akamai.net` | DNS resolver egress fingerprint |
| `yandex.ru`, `mail.ru`, `gosuslugi.ru` | RU latency anchors (HEAD) |
| `google.com`, `cloudflare.com`, `apple.com` | foreign latency anchors (HEAD) |
| `connectivitycheck.gstatic.com` | captive-portal probe |
| `stun.l.google.com:19302` | STUN mapped-address probe |
| `1.1.1.1`, `8.8.8.8`, `77.88.8.8` | traceroute anchors via `/system/bin/ping -t N` |

These services will log your exit IP, the timestamp, and possibly an HTTP
`User-Agent`. The OkHttp-based probes in the app:

- has no cookie jar (cookies are not stored)
- sends `User-Agent: vpn-detector/0.1` for the GeoIP probes; the latency anchors get OkHttp's default UA
- does not include any persistent device identifier
- does not transmit any request body — all calls are GET / HEAD
- runs nothing in the background; nothing is sent unless you tap the FAB

## Permissions

| Permission | Why |
|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE` | run probes, read network state |
| `ACCESS_FINE_LOCATION` | read Wi-Fi SSID (Android 10+ requires it for SSID — no GPS / location coordinates are read) |
| `QUERY_ALL_PACKAGES` | local scan for known VPN clients and Telegram forks |
| `PACKAGE_USAGE_STATS` | optional, granted manually via Settings → Apps → Special access → Usage access. Used only to check whether Telegram is currently running. |

## Build provenance

This APK is built from the source in this repository, signed with a self-managed keystore. The keystore lives at `keystore/release.jks` (gitignored) on the developer's machine.
