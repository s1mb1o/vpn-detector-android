package ru.shmelev.vpndetector.detect

import kotlinx.serialization.Serializable

@Serializable
enum class VerdictLevel { CLEAN, SUSPICIOUS, DETECTED }

@Serializable
data class Verdict(
    val level: VerdictLevel,
    val score: Int,
    val hardCount: Int,
    val softCount: Int,
)

object VerdictAggregator {
    fun aggregate(checks: List<Check>): Verdict {
        var score = 0
        var hard = 0
        var soft = 0
        for (c in checks) {
            when (c.severity) {
                Severity.HARD -> { score += 100; hard++ }
                Severity.SOFT -> { score += 10; soft++ }
                else -> {}
            }
        }
        val level = when {
            score >= 100 -> VerdictLevel.DETECTED
            score >= 30 -> VerdictLevel.SUSPICIOUS
            else -> VerdictLevel.CLEAN
        }
        return Verdict(level, score, hard, soft)
    }
}
