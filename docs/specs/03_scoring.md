# Scoring & Verdict Aggregation

How a single run is converted into the `CLEAN` / `SUSPICIOUS` / `DETECTED` banner shown in the verdict bar.

## Inputs

A run produces a flat `List<Check>` (typically ~35 rows) by concatenating the output of all four detector categories:

```
checks = SystemChecks.run(ctx)
       + GeoIpProbes.derive( GeoIpProbes.runAll() )
       + ConsistencyChecks.run(ctx, probes)
       + ActiveProbes.run()
```

Each `Check` carries one `Severity`:

| Severity | Meaning | Weight |
|---|---|---|
| `HARD` | Single occurrence is enough for an anti-fraud SDK to mark "VPN with high confidence" | **+100** |
| `SOFT` | Contributes to a score; a few of these together are detection-worthy | **+10** |
| `INFO` | Diagnostic context; never contributes | **0** |
| `PASS` | Observed value matches a clean RU resident profile | **0** |

`PASS` and `INFO` are visually distinct (green vs grey) but mathematically identical for scoring — neither moves the needle. Only `HARD` and `SOFT` add to the score.

## Aggregation

Implemented in `detect/Verdict.kt::VerdictAggregator.aggregate`:

```kotlin
score = 100 * (number of HARD checks) + 10 * (number of SOFT checks)

level = when {
    score >= 100 -> DETECTED      // any single HARD, OR ten SOFTs
    score >=  30 -> SUSPICIOUS    // three SOFTs, or borderline
    else         -> CLEAN
}
```

The aggregator also exposes the raw counts (`hardCount`, `softCount`) so the verdict bar can show them alongside the level.

## Why these thresholds

- **100 = single HARD** — by definition a HARD signal should already be enough; one is enough to flip to `DETECTED`. This means a HARD never gets diluted by surrounding PASSes.
- **30 = three SOFTs** — empirically the minimum where a real anti-fraud SDK starts ranking the device as suspicious. Two soft signals are common on legitimate setups (e.g. user with public DNS + an ad-blocker app installed); three usually means something is actually off.
- **10× ratio between HARD and SOFT** — large enough that no realistic combination of soft signals can mask a single HARD (you would need 10 soft hits, which is more soft signals than the catalog produces). This preserves the "any HARD ⇒ detected" guarantee.
- **No scaling for category** — every check, regardless of category, contributes the same weight as any other check of the same severity. We do not say "GeoIP HARD is worth more than System HARD". This keeps the rules transparent and easy to audit.

## How a check declares its severity

The severity is decided **inside the check function** at the moment it produces its `Check` row, based on the observed value. Two examples:

```kotlin
// SystemChecks: TRANSPORT_VPN
val isVpn = caps?.hasTransport(TRANSPORT_VPN) == true
Check(
    id = "transport_vpn",
    severity = if (isVpn) Severity.HARD else Severity.PASS,
    ...
)

// ConsistencyChecks: SIM country vs IP country
val mismatch = sim.isNotEmpty() && ipCountry != null && sim != ipCountry
Check(
    id = "sim_vs_ip",
    severity = if (mismatch) Severity.HARD else Severity.PASS,
    ...
)
```

There is **no second pass** that re-classifies severities. Whatever the check function decides is what gets aggregated. Adding a new rule = appending one function that returns a `Check` with the right severity; the aggregator picks it up automatically.

## Worked example — emulator validation run

Real run on Pixel 3a API 34 emulator (US SIM, host network in BG, no local VPN):

| Check | Severity | Why |
|---|---|---|
| `transport_vpn` (false) | PASS | No local VPN |
| `cap_not_vpn` (true) | PASS | — |
| `tun_iface` (none) | PASS | — |
| `active_iface_name` (`wlan0`) | PASS | — |
| `default_route_tun` (no) | PASS | — |
| `http_proxy` (none) | PASS | — |
| `private_dns` (off) | PASS | — |
| `dns_servers` (operator) | PASS | — |
| `installed_vpn_apps` (none) | PASS | — |
| `mtu` (1500) | PASS | — |
| `mock_location` (off) | PASS | — |
| `root` (stock) | PASS | — |
| `asn_class` ("DA International") | PASS | not a known datacenter keyword |
| `reputation_flag` (flagged) | **HARD** | one probe returned hosting=true |
| `probe_ip_agreement` (1 IP) | PASS | — |
| `sim_vs_ip` (US ≠ BG) | **HARD** | classic leak |
| `net_vs_ip` (US ≠ BG) | **HARD** | mirror of above |
| `carrier_vs_asn` (T-Mobile vs DA Intl) | PASS | not a RU carrier |
| `mcc_vs_ip` (310 vs BG) | PASS | MCC is not 250 (RU), so the rule doesn't fire |
| `locale_vs_ip` (US vs BG) | **SOFT** | mismatch |
| `lang_vs_ip` (en vs BG) | PASS | — |
| `tz_vs_ip` (UTC vs Sofia) | **SOFT** | mismatch |
| `lat_ru` (1145 ms) | **HARD** | > 200 ms |
| `lat_foreign` (1061 ms) | PASS | not < 30 ms |
| `lat_ratio` (foreign faster) | **HARD** | RU should be faster from a RU device |
| `captive_portal` (204) | PASS | — |

```
hardCount = 5    →  500
softCount = 2    →   20
score     = 520
level     = DETECTED   (520 ≥ 100)
```

The verdict bar shows: `DETECTED · score=520 · hard=5 · soft=2`. This matches the screenshot from the emulator validation in `ChangeLog.md`.

## Tuning the thresholds

If after running on a real RU phone the verdict comes back too noisy or too lenient, the only knobs are:

1. **Per-check severity** — change `Severity.SOFT` to `Severity.INFO` (or vice versa) inside the check function. Use INFO for any rule that produces too many false positives in real-world testing.
2. **Aggregator thresholds** — change the `100` / `30` cutoffs in `VerdictAggregator.aggregate`. Default is intentionally strict (any HARD = DETECTED).
3. **Weights** — change the `100` and `10` multipliers. Keeping the ratio ≥ 10× preserves the "any HARD ⇒ detected" property.

Document any change to weights or thresholds in `ChangeLog.md` along with the reason and the smoke-test scenario that motivated it.
