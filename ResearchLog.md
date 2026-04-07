# ResearchLog

## 2026-04-07

### Android VPN detection APIs (current)

- `ConnectivityManager.getNetworkCapabilities(activeNetwork).hasTransport(TRANSPORT_VPN)` — primary signal, available since API 21.
- `NetworkCapabilities.hasCapability(NET_CAPABILITY_NOT_VPN)` — mirror.
- `NetworkCapabilities.getUnderlyingNetworks()` — API 31+, returns the networks a VPN is built on top of. Non-empty = current network IS a VPN.
- `LinkProperties.routes` — checking for `0.0.0.0/0` via tun is the canonical "default route via VPN" check. Note WireGuard's `0.0.0.0/1` + `128.0.0.0/1` split-route trick on Android.
- `LinkProperties.privateDnsServerName` — DoT hostname when Private DNS is set explicitly.
- `NetworkInterface.getNetworkInterfaces()` — enumerate `tun*`, `tap*`, `wg*`, `utun*`, `ppp*`. Visible without `READ_PHONE_STATE`.

### GeoIP probe endpoints (free, no auth)

- `https://api.ipify.org?format=json` — IP only
- `https://ipinfo.io/json` — IP, country, region, city, org, timezone
- `http://ip-api.com/json/?fields=...` — adds `proxy`, `hosting`, `mobile` flags. Rate-limited to 45 req/min from a single IP.
- `https://ifconfig.co/json` — IP, country, ASN, ASN org, time_zone
- `https://api.myip.com` — IP, country, country_code
- `https://www.cloudflare.com/cdn-cgi/trace` — plain text k=v; reveals `warp=on` for Cloudflare WARP.

### Known datacenter ASN keywords (org-name substring match)

DigitalOcean, Amazon/AWS, Hetzner, OVH, Linode, Vultr/Choopa, Google Cloud, Microsoft/Azure, M247, Quadranet, Leaseweb, Cloudflare, DataCamp, Contabo, Scaleway, Online SAS.

### Open questions / future research

- True DNS leak test requires a controlled authoritative domain. Deferred until we register one.
- Is `Settings.Secure.always_on_vpn_app` readable on Android 14 without privileged perm? (Some OEM ROMs restrict.)
- Detecting Magisk Hide / Zygisk reliably from a non-root app — limited; current implementation is heuristic only.
