package net.vpndetector.detect

import net.vpndetector.data.model.RunResult

/**
 * History-aware checks. Detects rapid GeoIP country changes between consecutive runs.
 */
object HistoryChecks {

    fun run(currentGeoIp: List<Check>, previous: RunResult?): List<Check> {
        if (previous == null) return emptyList()
        val curr = currentGeoIp.firstOrNull { it.id == "external_country" }?.value?.uppercase()
        val prev = previous.checks.firstOrNull { it.id == "external_country" }?.value?.uppercase()
        if (curr.isNullOrEmpty() || prev.isNullOrEmpty() || curr == "?" || prev == "?") {
            return emptyList()
        }
        if (curr == prev) {
            return listOf(
                Check(
                    id = "country_history",
                    category = Category.GEOIP,
                    label = "External country stable across runs",
                    value = "$prev → $curr",
                    severity = Severity.PASS,
                    explanation = "External country has not changed between consecutive runs.",
                )
            )
        }
        val ageMs = (System.currentTimeMillis() - previous.timestamp).coerceAtLeast(0)
        val ageMin = ageMs / 60_000
        val ageHr = ageMin / 60.0
        val severity = when {
            ageMin < 60 -> Severity.HARD     // <1h: no plausible travel
            ageHr < 12 -> Severity.SOFT      // <12h: possible travel but suspicious
            else -> Severity.INFO            // >12h: travel is plausible
        }
        return listOf(
            Check(
                id = "country_history",
                category = Category.GEOIP,
                label = "External country changed across runs",
                value = "$prev → $curr  (${formatAge(ageMs)})",
                severity = severity,
                explanation = "External country flipped between consecutive runs. <1h gap = HARD " +
                    "(no plausible travel), <12h = SOFT, more = INFO.",
            )
        )
    }

    private fun formatAge(ms: Long): String {
        val s = ms / 1000
        return when {
            s < 60 -> "${s}s ago"
            s < 3600 -> "${s / 60}m ago"
            s < 86400 -> "${s / 3600}h ago"
            else -> "${s / 86400}d ago"
        }
    }
}
