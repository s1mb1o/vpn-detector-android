# Privacy

## No analytics, no telemetry

The app contains **no** analytics SDKs, crash reporters, telemetry frameworks, or third-party tracking libraries. Zero.

## What traffic does the app generate?

The only outbound network traffic is the diagnostic probes themselves:

| Destination | Protocol | Purpose |
|---|---|---|
| api.ipify.org | HTTPS | External IPv4 address |
| ipinfo.io | HTTPS | GeoIP (country, ASN, timezone) |
| ip-api.com | HTTP (free tier) | GeoIP + proxy/hosting flags |
| ifconfig.co | HTTPS | GeoIP (country, ASN) |
| api.myip.com | HTTPS | External IP + country |
| cloudflare.com/cdn-cgi/trace | HTTPS | Cloudflare location + warp status |
| api6.ipify.org | HTTPS | External IPv6 address |
| google.com, cloudflare.com, apple.com | HTTPS HEAD | Latency measurement |
| connectivitycheck.gstatic.com | HTTP | Captive portal detection (204) |
| ipinfo.io/{ip}/json | HTTPS | Per-hop GeoIP for traceroute |

**User-Agent** sent: `vpn-detector/0.4`

## What stays on device

- Run history (up to 50 entries) in Android DataStore (app-private storage)
- No cookies stored, no device identifiers transmitted
- No data leaves the device except the probes listed above

## Permissions

| Permission | Why |
|---|---|
| INTERNET | Network probes |
| ACCESS_NETWORK_STATE | Read active network properties |
| ACCESS_WIFI_STATE | Read Wi-Fi connection info |
| ACCESS_FINE_LOCATION | Wi-Fi SSID (Android 10+) |
| QUERY_ALL_PACKAGES | Scan for installed VPN/proxy apps |
| PACKAGE_USAGE_STATS | Detect running messaging apps (optional, manual grant) |
