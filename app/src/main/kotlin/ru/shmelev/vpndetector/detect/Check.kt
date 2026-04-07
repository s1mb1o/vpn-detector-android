package ru.shmelev.vpndetector.detect

import kotlinx.serialization.Serializable

/**
 * Severity classification used to weight a single signal in the verdict.
 *
 * - HARD : a single occurrence is enough for an anti-fraud SDK to flag the device.
 * - SOFT : contributes to a score; multiple soft hits together = detection.
 * - INFO : neutral diagnostic information; never affects the verdict.
 * - PASS : observed value is consistent with a clean RU resident profile.
 */
@Serializable
enum class Severity { HARD, SOFT, INFO, PASS }

@Serializable
enum class Category { SYSTEM, GEOIP, CONSISTENCY, PROBES }

@Serializable
data class Check(
    val id: String,
    val category: Category,
    val label: String,
    val value: String,
    val severity: Severity,
    val explanation: String,
)
