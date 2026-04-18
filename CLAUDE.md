# vpn-detector-android — project notes

Diagnostic Android app. Mirrors state-blocking / anti-fraud SDK detection logic. Used as feedback oracle for MikroTik tuning.

## Related

- Mikrotik repo: `~/Projects/10_admin/mikrotik`
- Blocking research: `~/Projects/10_admin/mikrotik/docs/rkn/`
- Plan: `~/.claude/plans/misty-doodling-candle.md`
- Source detection methodology: `~/Projects/10_admin/mikrotik/docs/rkn/vpn-detection-methodology.md`

## Architecture

- Single-module Android app, package `ru.shmelev.vpndetector`
- Kotlin + Compose Material 3, Coroutines, OkHttp, kotlinx.serialization, DataStore
- `detect/` is the engine; UI is fully data-driven from `Check` records
- Adding a new detection rule = one function returning a `Check`, then it appears automatically in its tab

## Adding a new check

1. Pick category (`SYSTEM` / `GEOIP` / `CONSISTENCY` / `PROBES`)
2. Add a function in the matching `*Checks.kt` / `*Probes.kt`
3. Return a `Check(id, category, label, value, severity, explanation)`
4. Severity rules: HARD = single-handed detection, SOFT = contributes to score, INFO = diagnostic, PASS = clean

## Build

See `README.md`.
