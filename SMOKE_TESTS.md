# Smoke tests

Manual scenarios. After every MikroTik change, re-run the relevant scenarios and compare history entries.

| # | Scenario | Expected verdict | Key signals |
|---|---|---|---|
| 1 | Mobile data, no WG, no home Wi-Fi | CLEAN | TRANSPORT_VPN=false, IP=RU, SIM/IP match |
| 2 | Home Wi-Fi, MikroTik default-route VPN | DETECTED | System CLEAN but Consistency FAIL (IP=non-RU vs SIM=RU). The leak. |
| 3 | Home Wi-Fi, MikroTik in whitelist mode (direct default, VPN only for antifilter list) | CLEAN | IP=RU residential, ASN matches home ISP |
| 4 | Mobile data + WG to home, full tunnel | DETECTED | TRANSPORT_VPN=true, tun iface present |
| 5 | Mobile data + WG split tunnel (per-app exclude detector) | CLEAN for this app | This app sees no VPN; other apps still tunneled |
| 6 | AmneziaWG vs plain WG | identical System tab | Confirms transport obfuscation does nothing for client-side detection |
| 7 | After enabling geo-probe direct rule on router (scenario 2 redux) | improves Consistency | GeoIP probes return RU |
| 8 | Roaming SIM + home Wi-Fi | INFO/PASS | SIM country may not be RU; consistency naturally consistent |
| 9 | Any stable direct network, no VPN/proxy | CLEAN + parity rows stable | `ref_ip_first_success` winner IP is also present in the parallel GeoIP set; `ref_host_reachability` is mostly/all reachable |
| 10 | Path with filtered Google push / selective host blocking | parity rows show the fingerprint | `ref_host_reachability` should highlight exactly which of `mtalk.google.com` / `gstatic.com` / `gosuslugi.ru` failed without disturbing the main VPN verdict |

Tag each history entry from the History tab (planned: text input on save) so before/after diffs are easy.
