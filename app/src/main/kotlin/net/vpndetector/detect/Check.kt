package net.vpndetector.detect

/**
 * Severity classification used to weight a single signal in the verdict.
 *
 * - HARD : a single occurrence is enough for an anti-fraud SDK to flag the device.
 * - SOFT : contributes to a score; multiple soft hits together = detection.
 * - INFO : neutral diagnostic information; never affects the verdict.
 * - PASS : observed value is consistent with a clean device profile.
 */
enum class Severity { HARD, SOFT, INFO, PASS }

enum class Category { SYSTEM, GEOIP, CONSISTENCY }

/** A single per-source row inside a Check's details, e.g. "ip-api → hosting=true". */
data class DetailEntry(
    val source: String,
    val reported: String,
    val verdict: Severity = Severity.INFO,
)

data class Check(
    val id: String,
    val category: Category,
    val label: String,
    val value: String,
    val severity: Severity,
    val explanation: String,
    /** Per-source breakdown shown in the details dialog. Empty if not applicable. */
    val details: List<DetailEntry> = emptyList(),
)
