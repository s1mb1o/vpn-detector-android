# Knowledge Base

Everything we have learned about the RU client-side anti-VPN detection methodology, our specific MikroTik + Pixel 8 setup, the threats we face, and the recipes that defeat (or fail to defeat) each detection signal.

This is the durable home for research and operator know-how. It complements the formal `docs/specs/` directory which describes the detection rules implemented in the app itself.

## What's where

| Document | Purpose |
|---|---|
| [`threat-model.md`](threat-model.md) | Threats, assets, mitigations matrix. Mirrored from the mikrotik repo. |
| [`adr-001-whitelist-routing.md`](adr-001-whitelist-routing.md) | Architecture decision record: invert the MikroTik routing default from `*.ru blacklist` to `antifilter whitelist`. |
| [`router-blueprint.md`](router-blueprint.md) | Empirical L3 topology of the home MikroTik (real traceroute data, IP/ASN/hop tables, fingerprint analysis). |
| [`operator-playbook.md`](operator-playbook.md) | Pragmatic step-by-step recipes for each operating mode (clean cellular, full bypass, home Wi-Fi, per-app exclude, residential RU exit, inverted routing). |

## How it relates to the rest of the project

```
docs/
├── source-methodology.md        ← cites the third-party RU methodology document
├── specs/                       ← formal detection rules implemented in the app
│   ├── 01_signal-catalog.md     ← every Check, FAIL/WARN/PASS conditions
│   ├── 02_architecture.md       ← engine + UI + data flow
│   ├── 03_scoring.md            ← VerdictAggregator weights and thresholds
│   ├── 04_proposed-checks.md    ← spec for the bypass-direction checks (DNS, blocked-domain, traceroute)
│   ├── 05_metrics-review.md     ← per-check audit, methodology mapping, false positives
│   └── 06_hiding-strategies.md  ← how to lower the score (operator-side advice)
└── knowledge-base/              ← THIS DIRECTORY
    ├── README.md                ← you are here
    ├── threat-model.md          ← what we defend against, why
    ├── adr-001-whitelist-routing.md   ← architecture decision
    ├── router-blueprint.md      ← actual MikroTik topology
    └── operator-playbook.md     ← pragmatic recipes
```

`specs/` answers "**what** does the app detect"; `knowledge-base/` answers "**why** is the threat real and **how** do we work with it on the network side". The two cross-reference each other — every check in `05_metrics-review.md` has a corresponding mitigation entry in `06_hiding-strategies.md`, and the whole story ties back to the `threat-model.md`.

## Reading order

If you (or a future Claude session, or a friend you handed the APK to) need to understand the full picture, read in this order:

1. [`../source-methodology.md`](../source-methodology.md) — the published RU methodology this whole project mirrors
2. [`threat-model.md`](threat-model.md) — what we are actually defending against on our specific setup
3. [`router-blueprint.md`](router-blueprint.md) — what the actual L3 topology of the MikroTik looks like, with real traceroute data
4. [`../specs/05_metrics-review.md`](../specs/05_metrics-review.md) — the catalog of detection rules this app implements
5. [`../specs/06_hiding-strategies.md`](../specs/06_hiding-strategies.md) — strategies, ranked by tier
6. [`operator-playbook.md`](operator-playbook.md) — concrete step-by-step recipes
7. [`adr-001-whitelist-routing.md`](adr-001-whitelist-routing.md) — the structural fix on the MikroTik side

## External references

Documents that live outside this repo but are part of the same body of knowledge:

| Path | Purpose |
|---|---|
| `~/Projects/10_admin/mikrotik/` | The MikroTik configuration repo. ChangeLog tracks every router-side change. |
| `~/Projects/10_admin/mikrotik/docs/rkn/threat-model.md` | Original of `threat-model.md`. This file is the authoritative copy when there's disagreement (it lives with the actual configs). |
| `~/Projects/10_admin/mikrotik/docs/rkn/architecture-decision-whitelist-vpn.md` | Original of `adr-001-whitelist-routing.md`. |
| `~/Projects/10_admin/mikrotik/docs/plans/` | Implementation plans for AmneziaWG, VLESS-Reality, etc. Numbered sequentially. |
| `~/Projects/10_admin/mikrotik/src/sync-antifilter/` | The antifilter list source used by the routing decisions in ADR-001. |
| `~/.claude/plans/misty-doodling-candle.md` | The original implementation plan for this Android app, kept for historical context. |

## Maintenance rules

- **One source of truth per fact.** When the same idea appears in two docs, one of them links to the other instead of duplicating.
- **Empirical over theoretical.** When a real-device run contradicts a doc, update the doc with the new measurement and date the change in `ChangeLog.md`.
- **Always cite the methodology section.** Every detection rule and every mitigation should reference the source paragraph in `source-methodology.md` (e.g. "methodology §6.4"). This makes it easy to audit later.
- **Validation harness lives in `tools/`.** Never lose the ability to re-run `tools/traceroute.sh` against a connected device. If you change a router, re-run and update `router-blueprint.md`.
