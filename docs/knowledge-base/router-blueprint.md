# Router Blueprint — actual MikroTik topology from traceroute mapping

This is the empirical map of the home MikroTik setup as observed from a Pixel 8 over USB ADB across two test sessions. It documents the exact L3 path the device produces, what each hop is, and how that maps to the detection signals in `docs/specs/05_metrics-review.md`.

The point of writing this down is that **the topology is itself a fingerprint**: the sequence of hops your phone produces is unique to a router-with-VPN-containers setup, distinct from a vanilla residential router. Any change you make on the MikroTik side should be re-validated against this baseline using `tools/traceroute.sh`.

## Reference: MikroTik upstream

| Property | Value |
|---|---|
| Router | MikroTik hAP ax³ (popov47-hap-ax3), 192.168.86.1 |
| RouterOS | 7.21 |
| Tunnel containers | Docker bridge `172.17.0.0/16` (Docker default), AmneziaWG client(s) on `10.10.0.0/24`, upstream provider in-tunnel transit on `10.0.1.0/24` |
| Upstream VPN exit | AS203380 DA International Group Ltd., Sofia, BG |
| Visible exit IP (SNAT public face) | `91.148.132.84` |
| Upstream provider transit | AS57344 Telehouse EAD, Sofia, BG |

## Reference: Pixel 8 client

| Property | Value |
|---|---|
| Wi-Fi address | `192.168.86.51/24` |
| Cellular | MegaFon, MCC 250 (RU), AS25159 / AS31133 |
| Cellular IP (typical) | e.g. `31.173.84.78` (clean RU) |
| First MegaFon transit hop visible | e.g. `83.169.204.114` Moscow, AS31133 PJSC MegaFon |

## L3 path on home Wi-Fi (no VPN on phone) → 1.1.1.1

```
hop  1: 192.168.86.1     LAN gateway (MikroTik LAN side)             RFC1918
hop  2: 172.17.0.12      Docker default bridge inside the router     RFC1918
hop  3: 10.10.0.1        WG / AmneziaWG client interface in router   RFC1918
hop  4: 78.128.99.1      first non-RFC1918 hop, BG Sofia, AS203380   ← FIRST PUBLIC
hop  5: 10.0.1.1         in-tunnel hop on the upstream provider      RFC1918
hop  6: 94.72.150.178    BG Sofia                                    public
hop  7: 178.132.82.74    BG Sofia, AS57344 Telehouse EAD             public
hop  8: 178.132.81.234   BG Sofia, AS57344 Telehouse EAD             public
hop  9: 1.1.1.1          AU Brisbane, AS13335 Cloudflare             dest
```

**Fingerprint of this topology:** `192.168.86.1 → 172.17.x → 10.10.x → BG public`. Two consecutive RFC1918 hops *after* the LAN gateway is the unique signature of a router with containerised tunnel clients. A vanilla residential router decrements TTL once and the next hop is the ISP — no `172.17.x`, no `10.10.x`.

The `10.0.1.1` in hop 5, sandwiched between two BG public hops, is the in-tunnel address space of the upstream VPN provider. Not used by any Check directly, just a recurring feature of the trace.

## L3 path on cellular with phone-side WG to home → 1.1.1.1

```
hop  1: 172.30.0.1       phone's wg tun interface                    RFC1918
hop  2: 172.17.0.12      router Docker bridge                        RFC1918
hop  3: 10.10.0.1        router WG / AmneziaWG client                RFC1918
hop  4: 78.128.99.1      first public hop, BG Sofia, AS203380
hop  5: 10.0.1.1         in-tunnel
hop  6: 94.72.150.178    BG Sofia
hop  7: 178.132.82.74    BG Sofia
hop  8: 178.132.81.234   BG Sofia
hop  9: 1.1.1.1          AU Brisbane, AS13335 Cloudflare
```

The only difference vs the home-Wi-Fi path: hop 1 is the **phone's** WG tun (`172.30.0.1`) instead of the LAN gateway (`192.168.86.1`). Everything from hop 2 onward is identical because the phone's WG terminates inside the same MikroTik that hosts the upstream tunnel containers.

## L3 path on clean cellular (no VPN at all) → 1.1.1.1

```
hop  1..10: * (no reply)         MegaFon transit drops ICMP TTL exceeded
hop 11: 83.169.204.114   Moscow, AS31133 PJSC MegaFon                ← FIRST PUBLIC
hop 12..13: * (no reply)
hop 14: 162.158.236.13   FI Helsinki, AS13335 Cloudflare
hop 15: 1.1.1.1          AU Brisbane, AS13335 Cloudflare
```

MegaFon throttles ICMP TTL-exceeded for the first ~10 hops. The first non-RFC1918 hop that *does* reply is in Moscow on MegaFon's own AS — Check C (`router_egress_country`) correctly degrades to PASS because the first non-`*` public hop matches SIM=RU.

## How each L3 path maps to scoring

| Path | `transport_vpn` | `tun_iface` | `default_route_tun` | `external_country` | `router_egress_country` | matrix |
|---|---|---|---|---|---|---|
| Wi-Fi @ home, no phone VPN | PASS | PASS | PASS | BG (FAIL) | hop 4 = BG ≠ RU → FAIL | `BYPASS_DETECTED` |
| Cellular + phone WG to home | FAIL (`tun0`) | FAIL | FAIL | BG (FAIL) | FAIL | `BYPASS_DETECTED` |
| Clean cellular, no VPN | PASS | PASS | PASS | RU (PASS) | hop 11 = RU → PASS | `BYPASS_NOT_DETECTED` |

The **GeoIP / Consistency axis** fires whenever the MikroTik upstream is BG. The only way to make this axis stop firing is to switch the upstream to a residential RU exit (Tier 3 in `06_hiding-strategies.md`).

## Where each signal comes from in the topology

| Signal | Layer | Source |
|---|---|---|
| `transport_vpn` / `tun_iface` / `default_route_tun` / `vpn_transport_info` | phone | phone-side WG/AmneziaVPN client only — disappear if tunnel is on the router |
| `mtu = 1280` | phone | WG default — disappears with router-only tunnel |
| `route_anomalies` (5 routes via tunnel) | phone | phone-side WG split-route trick — disappears with router-only tunnel |
| `external_country` BG, `sim_vs_ip` FAIL etc. | upstream | exit ASN/IP — only fixable by changing the MikroTik upstream |
| `reputation_flag hosting=true` | upstream | datacenter ASN — fixable by residential exit |
| `router_egress_country` first non-RFC1918 hop = BG | upstream | the Sofia exit pops out at hop 4 — same fix |
| `country_history` HARD on flip | session | only fires after at least one prior run with a different country |

## Remediation matrix (cross-reference with `06_hiding-strategies.md`)

| Want to silence... | Do this |
|---|---|
| Direct axis (6 HARDs at once) | move tunnel off the phone — use Wi-Fi at home, or use a portable WG-router downstream of cellular |
| GeoIP / Consistency axis | switch MikroTik upstream from BG datacenter (AS203380) to a residential RU exit |
| `router_egress_country` only | same — first non-RFC1918 hop is the exit |
| `transparent_proxy_headers` | already whitelisted for `via=1.1 google` etc.; if it fires for an unknown header, investigate the path |
| `country_history` after a mode switch | wait > 1h between runs across exit changes (HARD → SOFT after 1h, INFO after 12h) |
| `installed_vpn_apps` SOFT | uninstall WireGuard official + OpenVPN if not used (you use AmneziaVPN) |
| `telegram_present` SOFT | move Telegram to a work profile, or accept it |

## Validation harness

Re-run after every router change:

```bash
~/Projects/40_pet/vpn-detector-android/tools/traceroute.sh
# or for a specific device serial:
~/Projects/40_pet/vpn-detector-android/tools/traceroute.sh 1.1.1.1 15 41231FDJH002WZ
```

Then install / launch the app and:

```bash
adb logcat -c
adb shell am start -n net.vpndetector/.MainActivity
# tap "Run all checks" on the phone
adb logcat -d -s VpnDetector:I > /tmp/run_$(date +%s).log
```

Compare the new run's `score=` and `matrix=` against the reference rows in this document. If anything moved, update this file with the new baseline.
