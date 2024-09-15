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

enum class Category { SYSTEM }

data class Check(
    val id: String,
    val category: Category,
    val label: String,
    val value: String,
    val severity: Severity,
    val explanation: String,
)
