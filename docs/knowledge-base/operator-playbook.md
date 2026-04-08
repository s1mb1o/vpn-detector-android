# Operator Playbook

Pragmatic, opinionated step-by-step recipes for the dual-end Pixel 8 + MikroTik setup. Each recipe ends with the expected score/matrix label so you can verify success with `adb logcat -s VpnDetector:I`.

Cross-references:
- [`threat-model.md`](threat-model.md) — what we are defending against and why
- [`adr-001-whitelist-routing.md`](adr-001-whitelist-routing.md) — the inverted-routing decision
- [`router-blueprint.md`](router-blueprint.md) — actual L3 topology and per-mode score table
- [`../specs/05_metrics-review.md`](../specs/05_metrics-review.md) — every detection rule
- [`../specs/06_hiding-strategies.md`](../specs/06_hiding-strategies.md) — strategy tiers

## Modes

The phone has four practical operating modes. Each has different observable signals.

| # | Mode | Tunnel | Geo | Direct axis | Use case |
|---|---|---|---|---|---|
| 1 | Cellular, no VPN | none | RU | clean | banking, госуслуги, fraud-sensitive apps |
| 2 | Cellular + WG to home | phone-side | BG (via router) | fires | YouTube/ChatGPT/etc on the go |
| 3 | Home Wi-Fi, no phone VPN | router-side | BG (via router) | clean | YouTube/ChatGPT/etc at home, banking still works through per-host overrides |
| 4 | Home Wi-Fi + per-app exclude on the WG client | per-app | mixed | clean for excluded apps | hybrid: bypass for blocked sites, banks see clean RU |

Mode 3 is the daily-driver target. Mode 1 is the safety mode. Mode 2 is the worst — both axes fire simultaneously.

---

## Recipe 1 — clean RU baseline (banking mode)

**Goal:** appear as a normal RU MegaFon resident. Score floor for the device.

**Steps:**
1. Disconnect from any Wi-Fi network (or move out of range).
2. On the phone's WG / AmneziaVPN client: tap the toggle to disable.
3. (Optional) Open AmneziaVPN → Menu → Disconnect from active config.

**Expected verdict:**
```
verdict   = SUSPICIOUS  score=30  hard=0  soft=3
matrix    = BYPASS_NOT_DETECTED  (geoip=false direct=false indirect=false)
```

The remaining `score=30` is `installed_vpn_apps` (WireGuard/OpenVPN packages) + `lat_ru` (cellular >400ms) + `telegram_present`. None of those mean "currently bypassing".

**Use this mode for:** opening the bank app, госуслуги, marketplaces, apps that have anti-fraud SDKs.

---

## Recipe 2 — full bypass (worst from a detection standpoint)

**Goal:** route all phone traffic through the home WG → BG exit.

**Steps:**
1. On the phone WG/AmneziaVPN client: enable the home tunnel profile.
2. Profile uses default `AllowedIPs = 0.0.0.0/0` so the phone gets a default route through `tun0`.

**Expected verdict (validated 2026-04-08 on Pixel 8):**
```
verdict   = DETECTED  score=1390  hard=13  soft=9
matrix    = BYPASS_DETECTED  (geoip=true direct=true indirect=true)
```

13 HARD signals: 6 direct (transport_vpn family), ~5 GeoIP/consistency (BG vs RU), ~2 indirect (router_egress_country, country_history if you mode-switched within an hour).

**Don't use this for fraud-sensitive apps.** Use it only for apps that don't have detection SDKs (browser, messengers, video).

---

## Recipe 3 — home Wi-Fi, all bypass via router

**Goal:** no tunnel on the phone at all; the MikroTik does all the bypass; phone sees a normal Wi-Fi interface.

**Steps:**
1. Connect to your home Wi-Fi (`Roci-2.4GHz` or whichever).
2. On the phone WG/AmneziaVPN client: **disable the active profile**. Even though you're at home, leaving it on creates `tun0` and fires the entire direct axis.
3. (Optional) Set up Tasker / iOS Shortcuts automation: when SSID == home, force-disable VPN.

**Expected verdict on the current MikroTik with BG upstream:**
```
verdict   = DETECTED  score=~600-700  hard=~6  soft=~3
matrix    = BYPASS_DETECTED  (geoip=true direct=false indirect=true)
```

Direct axis is **clean** (PASS for `transport_vpn`, `tun_iface`, `default_route_tun`, `vpn_transport_info`). What still fires:

- Entire GeoIP/consistency axis because the router exit is BG, not RU
- `router_egress_country` because hop 4 is BG (matches the topology in `router-blueprint.md`)
- `installed_vpn_apps` SOFT (WireGuard/OpenVPN packages), `telegram_present` SOFT

To eliminate the GeoIP axis, see Recipe 5 (residential RU exit on the MikroTik).

---

## Recipe 4 — per-app exclude (the methodology blind spot)

**Goal:** keep WG on the phone for general bypass, but make specific apps see a clean RU view.

**Why:** methodology §7.9 explicitly cites this as the documented blind spot — "Proxy-in-app, кастомные туннели и пользовательские реализации обхода, не отражающиеся в системных API". An anti-fraud SDK in an app excluded from the tunnel cannot see the tunnel because the OS routes around it before the SDK gets a chance to look.

**Steps in AmneziaVPN client:**
1. Open AmneziaVPN → Settings (gear icon) → Connection / Application split tunneling
2. Select "Don't use VPN for selected apps" (exclude mode)
3. Tick the apps that need to look like clean RU residents:
   - Bank apps: Sberbank, Tinkoff, Alfa-Bank, VTB, Raiffeisen, Otkritie, etc.
   - Government: Госуслуги, ФНС, Личный кабинет ПФР
   - Marketplaces: Wildberries, Ozon, Yandex Market, Avito
   - Delivery: Yandex Eda, Delivery Club, Самокат, Vкусно — и точка
   - Taxi: Yandex Go
   - Anything that runs an anti-fraud SDK
4. Add `net.vpndetector` to the exclude list — the harness then validates that the per-app exclude is correctly configured.
5. Save and reconnect the tunnel.

**Steps in WireGuard official client:**
1. Open the tunnel config → "Edit" → "All applications"
2. Choose "Excluded applications", tick the same set as above

**Expected verdict** with `net.vpndetector` excluded:
```
verdict   = SUSPICIOUS  score=30  hard=0  soft=3
matrix    = BYPASS_NOT_DETECTED  (geoip=false direct=false indirect=false)
```

Same as Recipe 1, even though the tunnel is up. The detector's process exits via cellular `rmnet1` and looks identical to a clean RU device. The bank app, also excluded, gets the same view.

**Verification:** after configuring per-app exclude, run the detector. If you see anything other than `BYPASS_NOT_DETECTED` for the excluded app, the exclude is not active.

**Limitation:** any app NOT on the exclude list still sees the tunnel — but that's by design.

---

## Recipe 5 — switch the MikroTik upstream to a residential RU exit

**Goal:** eliminate the GeoIP axis entirely, even when the tunnel is on.

**Why:** the current MikroTik upstream is AS203380 DA International in Sofia, BG. That single fact drives 6 of the 13 HARDs in Recipe 2 (`external_country`, `sim_vs_ip`, `net_vs_ip`, `mcc_vs_ip`, `carrier_vs_asn`, `reputation_flag`, `router_egress_country`). A residential RU exit would PASS all of those.

**Steps (high-level — implementation lives in the mikrotik repo):**
1. Provision a residential proxy / tunnel endpoint in RU (paid residential proxy provider, friend's home WG, second small MikroTik on a relative's RU residential ISP, etc.)
2. On the popov47-hap-ax3 MikroTik: add the new exit as a second AmneziaWG / WG client interface.
3. Update mangle rules to mark traffic for `vpn-whitelist` (sync-antifilter) → routing-mark `vpn-residential` instead of the current BG mark.
4. Test from the home Wi-Fi: `curl https://ipinfo.io/json` should return RU IP, RU country, RU residential ASN org.
5. Re-run the detector — the GeoIP axis should now be PASS.

**Expected verdict after Recipe 5 + Recipe 3:**
```
verdict   = SUSPICIOUS or CLEAN  score=~30  hard=0  soft=~3
matrix    = BYPASS_NOT_DETECTED  (geoip=false direct=false indirect=false)
```

**Cost:** finding a stable residential RU exit is hard. Most paid residential proxies are mobile-rotation pools, which have their own footprint. A friend's home WG is the best option but requires a friend.

---

## Recipe 6 — invert routing default (ADR-001)

**Goal:** make the MikroTik a "VPN by whitelist" router instead of "direct by `*.ru` blacklist". This is the structural fix from `adr-001-whitelist-routing.md`.

**Effect:** any unknown / probe / not-on-the-antifilter-list domain goes direct → RU IP → consistent. Eliminates GeoIP-axis leaks for **everything** that isn't on the antifilter list. Banking apps that probe `ipinfo.io` get RU even on home Wi-Fi without per-app exclusion.

**Migration steps from the ADR:**
1. Snapshot current mangle rules.
2. Create address-list `vpn-whitelist` from sync-antifilter.
3. Create address-list `geoip-probe-direct` (override layer for probe hosts: `ipify.org`, `ipinfo.io`, `ip-api.com`, `ifconfig.co`, `myip.com`, `icanhazip.com`, `checkip.amazonaws.com`, `connectivitycheck.gstatic.com`, `captive.apple.com`).
4. Rewrite mangle: mark-routing `vpn-whitelist` → vpn exit; `geoip-probe-direct` → main table (override).
5. Remove the obsolete `*.ru direct` rule (becomes redundant).
6. Test: `curl ipinfo.io` from home Wi-Fi must return RU.

**Expected verdict with Recipe 6 + Recipe 3:**
```
verdict   = SUSPICIOUS or CLEAN  score=~30  hard=0  soft=~3
matrix    = BYPASS_NOT_DETECTED  (geoip=false direct=false indirect=false)
```

---

## Recipe 7 — daily ritual

The minimum-friction routine for someone who lives with this setup:

**Morning (at home):**
1. Phone connects to home Wi-Fi automatically.
2. Tasker rule: SSID == home → disable WG profile. (Recipe 3 mode.)
3. Bypass works through the router. Banking apps work through Recipe 4 per-app exclude or Recipe 6 inverted routing.

**Out of home (cellular):**
1. If you need to look at a blocked site briefly: enable WG. (Recipe 2.)
2. Before opening a banking app: disable WG. (Recipe 1.) Or rely on per-app exclude (Recipe 4) and never toggle.
3. Tasker rule: when leaving home Wi-Fi, do **not** auto-enable WG — make it manual so you don't accidentally trigger Recipe 2 in front of a fraud SDK.

---

## Smoke tests after every change

Use `tools/traceroute.sh` for the L3-only check (no APK required), and the detector app for the full check.

```bash
# Quick L3 sanity (router topology, 2 seconds)
~/Projects/40_pet/vpn-detector-android/tools/traceroute.sh 1.1.1.1 15 41231FDJH002WZ

# Full detector run (15-30 seconds for traceroute + GeoIP probes)
adb -s 41231FDJH002WZ logcat -c
adb -s 41231FDJH002WZ shell am start -n net.vpndetector/.MainActivity
# tap "Run all checks" on the phone
sleep 30
adb -s 41231FDJH002WZ logcat -d -s VpnDetector:I > /tmp/run_$(date +%s).log
grep -E '===== run|matrix=|\[FAIL\]' /tmp/run_$(date +%s).log
```

Compare against the reference rows in `router-blueprint.md`. If `score=` moved unexpectedly, look at the per-axis matrix flags and the per-row FAIL list.

---

## Quick reference card

| Mode | Direct axis | GeoIP axis | Score floor | Verdict |
|---|---|---|---|---|
| 1. Clean cellular | clean | clean | 30 | `BYPASS_NOT_DETECTED` |
| 2. Cellular + phone WG | fires | fires | 1390 | `BYPASS_DETECTED` |
| 3. Home Wi-Fi (current MT, BG exit) | clean | fires | ~600 | `BYPASS_DETECTED` |
| 3 + Recipe 5 (residential RU exit) | clean | clean | ~30 | `BYPASS_NOT_DETECTED` |
| 4. Per-app exclude on WG | clean *for excluded apps* | clean *for excluded apps* | ~30 | `BYPASS_NOT_DETECTED` |
| 6. Inverted routing (ADR-001) | clean | clean for non-whitelisted apps | ~30 | `BYPASS_NOT_DETECTED` |

The two structural fixes (Recipe 5 and Recipe 6) are the most important — both achieve clean detection on the home Wi-Fi without requiring discipline on the phone side.
