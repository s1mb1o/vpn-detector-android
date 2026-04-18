package net.vpndetector.detect

import net.vpndetector.AppStrings
import net.vpndetector.R
import net.vpndetector.data.model.RunResult

/**
 * History-aware checks. Methodology §5.4 step 5 — "compare with the history of past sessions".
 *
 * Currently produces one row: rapid GeoIP-country change between two adjacent runs.
 * If a device's external country flips within a short window with no plausible travel,
 * the user has switched VPN states between the runs.
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
                    label = AppStrings.get(R.string.check_country_history_stable_label),
                    value = AppStrings.get(R.string.val_country_transition, prev, curr),
                    severity = Severity.PASS,
                    explanation = AppStrings.get(R.string.check_country_history_stable_explanation),
                )
            )
        }
        val ageMs = (System.currentTimeMillis() - previous.timestamp).coerceAtLeast(0)
        val ageMin = ageMs / 60_000
        val ageHr = ageMin / 60.0
        val severity = when {
            ageMin < 60 -> Severity.HARD
            ageHr < 12 -> Severity.SOFT
            else -> Severity.INFO
        }
        return listOf(
            Check(
                id = "country_history",
                category = Category.GEOIP,
                label = AppStrings.get(R.string.check_country_history_changed_label),
                value = AppStrings.get(R.string.val_country_transition_with_age, prev, curr, formatAge(ageMs)),
                severity = severity,
                explanation = AppStrings.get(R.string.check_country_history_changed_explanation),
            )
        )
    }

    private fun formatAge(ms: Long): String {
        val s = ms / 1000
        return when {
            s < 60 -> AppStrings.get(R.string.val_age_seconds, s.toInt())
            s < 3600 -> AppStrings.get(R.string.val_age_minutes, (s / 60).toInt())
            s < 86400 -> AppStrings.get(R.string.val_age_hours, (s / 3600).toInt())
            else -> AppStrings.get(R.string.val_age_days, (s / 86400).toInt())
        }
    }
}
