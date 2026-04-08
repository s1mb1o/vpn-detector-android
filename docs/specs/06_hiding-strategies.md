# Hiding strategies — how to lower the score on a real device

This document captures real-world test results and the architectural advice derived from them. It is the operator-side companion to `05_metrics-review.md` (which catalogs the detection rules) — here we explain how to *defeat* those rules on a device you control.

## Reference run

Pixel 8, MegaFon LTE in RU, WireGuard client on the phone tunneling all traffic to a home MikroTik in Bulgaria (the MikroTik then forwards non-`*.ru` through a BG exit).

```
verdict = DETECTED   score=1390   hard=13   soft=9
matrix  = BYPASS_DETECTED   (geoip=true direct=true indirect=true)
```

All three methodology axes fired. Worst possible verdict.

### What fires (and why)

#### Direct axis — cannot be hidden without root or per-app exclusion

| Check | Why |
|---|---|
| `transport_vpn` true | Phone's WG client owns the active network |
| `cap_not_vpn` false | Mirror of TRANSPORT_VPN |
| `tun_iface` `tun0` | WG tunnel interface is UP |
| `active_iface_name` `tun0` | Default network is the tunnel |
| `default_route_tun` yes | `0.0.0.0/0` via `tun0` |
| `vpn_transport_info` `VpnTransportInfo{type=1, sessionId=null, bypassable=false}` | API 31+ exposes the VPN session object |

#### GeoIP / consistency axis — cannot be hidden, reflects observable reality

| Check | Why |
|---|---|
| `external_country` BG | Exit IP `91.148.132.84` BG AS203380 |
| `sim_vs_ip` / `mcc_vs_ip` / `net_vs_ip` / `carrier_vs_asn` FAIL | SIM=RU MegaFon vs IP=BG |
| `reputation_flag` flagged | ip-api: `hosting=true` on the BG datacenter exit |
| `country_history` FAIL `RU → BG` 3m ago | Previous run was clean RU; <1h gap → HARD |

#### Indirect axis

| Check | Why |
|---|---|
| `router_egress_country` FAIL: hop 4 = `78.128.99.1` BG, ≠ SIM=RU | First non-RFC1918 hop resolves to BG |
| `mtu` 1280 SOFT | Classic WG MTU |
| `route_anomalies` SOFT: 5 routes via tunnel | Split-routing inside WG |
| `installed_vpn_apps` SOFT | WireGuard, OpenVPN |
| `telegram_present` SOFT | Telegram installed |

The traceroute path matches the previous session's mapping: phone's `tun0` → router's Docker bridge `172.17.0.12` → router's WG client `10.10.0.1` → BG public exit `78.128.99.1`. The router-side topology is fully visible from the phone's L3 path.

---

## Strategies to lower the score

Ranked by effectiveness vs cost.

### Tier 1 — eliminate the direct axis (the only way to drop 6 HARDs at once)

**Move the tunnel off the phone entirely.** The `transport_vpn` family is unhideable without root because Android *by design* exposes any active VPN to any app via `ConnectivityManager`. The only fix is to **stop running WG on the phone** and instead get the bypass from the router via plain Wi-Fi:

- Connect the phone to your home Wi-Fi (or to a portable router that does WG client → upstream WG to your MikroTik). The router does the tunneling; the phone sees a normal Wi-Fi interface, no `tun0`, no `TRANSPORT_VPN`.
- For mobile contexts where home Wi-Fi isn't available: a small travel router (GL.iNet Beryl/Slate-AX) terminating WG against your MikroTik, with the phone connected to it via Wi-Fi. Same effect, anywhere you have power.

This single change removes: `transport_vpn`, `cap_not_vpn`, `tun_iface`, `active_iface_name`, `default_route_tun`, `vpn_transport_info`, `mtu`, `route_anomalies`. **8 signals at once.** It's the only architectural change that defeats the direct axis cleanly.

### Tier 2 — exclude sensitive apps from the WG tunnel (per-app split routing)

If you must keep WG on the phone, the AmneziaVPN / WireGuard for Android client supports **per-app split tunnel** (Settings → All applications → exclude). Add `net.vpndetector` (and any banking/госуслуги apps) to the exclude list.

For an excluded app the result is dramatic — its traffic exits via the cellular `rmnet1` instead of `tun0`, so:

- `transport_vpn`, `cap_not_vpn`, `tun_iface`, `active_iface_name`, `default_route_tun`, `vpn_transport_info` **all flip to PASS** for that app's process
- `external_country` reverts to RU (cellular IP)
- `sim_vs_ip` / `mcc_vs_ip` / `net_vs_ip` / `carrier_vs_asn` **all PASS**
- `router_egress_country` PASS (cellular path goes straight to MegaFon)
- `country_history` PASS

A real anti-fraud SDK in a banking app, also excluded from the tunnel, sees the same clean view.

**This is the right approach for the actual банк/госуслуги use case.** Per-app exclude is the methodology's documented blind spot (§7.9 — *"Proxy-in-app, кастомные туннели и пользовательские реализации обхода, не отражающиеся в системных API"*). The fraud SDK literally cannot see what the OS routes around it.

Catch: the detector then *also* reports "clean" — which is meaningful only as confirmation that the per-app exclude is set correctly for **this** app. To actually test bypass effectiveness on a different app (e.g. the banking app), that other app would need to run its own checks. Our tool just confirms "from the perspective of an excluded app, your device looks like a normal RU resident".

### Tier 3 — reduce the GeoIP fingerprint of the bypass exit itself

These help even when the tunnel stays on:

1. **Use a residential RU exit instead of a BG datacenter.** AS203380 DA International (current BG host) trips `asn_class`-class checks (the methodology's reputation lists) and the consistency cross-checks (BG ≠ RU). A residential proxy in RU on a major ISP ASN would PASS `external_country`, `sim_vs_ip`, `net_vs_ip`, `mcc_vs_ip`, `carrier_vs_asn`, `router_egress_country`. Single biggest GeoIP-axis improvement available without changing the architecture.
2. **Pick an exit IP not in any reputation list.** ip-api flagged `hosting=true` on the current exit; that drives `reputation_flag` HARD on its own. A clean residential IP is invisible to public reputation databases.

If the exit changes to a residential RU IP and the tunnel stays on the phone, the score drops from `13 HARD / 9 SOFT` to roughly `6 direct HARDs (unhideable) + ~3 indirect SOFTs`. About half.

### Tier 4 — reduce the indirect / contextual noise

Each of these subtracts 10 from the score:

1. **Uninstall `com.wireguard.android` and `net.openvpn.openvpn`** if you don't actually use them (you use AmneziaVPN). Drops `installed_vpn_apps` SOFT.
2. **Remove Telegram, or move it to a work profile.** Drops `telegram_present` SOFT.
3. **Wait > 1h between runs** when changing exit countries. The `country_history` check goes from HARD → SOFT after 1h, SOFT → INFO after 12h. Can't avoid the signal entirely if your IP keeps flipping, but you can lower its severity.
4. **MTU.** WG just is 1280. AmneziaWG can use 1380 or 1500 — switch to AmneziaWG with `MTU = 1500` and a matching upstream and this row PASSes.

### Tier 5 — what NOT to bother with

- **Spoofing SIM country / locale / timezone** — requires root, breaks other apps, and a fraud SDK that knows the methodology will cross-check differently anyway.
- **Trying to hide the `tun0` interface name** — the iface lives in the kernel namespace, no root = no hide.
- **Using AmneziaWG instead of WG *for client-side hiding*** — AWG defeats DPI on the wire, not on-device. The on-device signals (`tun0`, `TRANSPORT_VPN`, `default_route_tun`) are identical because both create a system-level VPN. AWG helps the router-side bypass survive TSPU; it does not reduce client-side detection at all.

---

## Recommended setup

Given you control both ends (Pixel 8 + MikroTik):

1. **Per-app exclude** on the WG / AmneziaVPN client for `net.vpndetector` and every RU bank/госуслуги/marketplace app you actually use → those apps drop entirely off the direct axis.
2. **Switch the MikroTik upstream to a residential RU exit** (or accept the BG exit and the GeoIP axis cost when the tunnel does need to be on).
3. **Uninstall WireGuard official + OpenVPN** if you don't use them → one SOFT noise item gone.
4. **Default to home-Wi-Fi mode when at home** — the phone has no tunnel at all, only DNS goes via the router.

## Validation methodology

After each change, re-run the harness via `adb logcat -s VpnDetector:I` (with the device on USB) and compare:

- `score=` should drop
- `hard=` count should drop
- `matrix=` should ideally move from `BYPASS_DETECTED` toward `BYPASS_NOT_DETECTED`
- The per-axis flags `geoip=Y direct=Y indirect=Y` show which axes are still firing

The reference clean RU cellular run (no VPN) achieved `score=30 hard=0 soft=3 matrix=BYPASS_NOT_DETECTED(geoip=false direct=false indirect=false)` — that's the floor for this device with these installed apps. Anything above that is the cost of whatever bypass is currently active.
