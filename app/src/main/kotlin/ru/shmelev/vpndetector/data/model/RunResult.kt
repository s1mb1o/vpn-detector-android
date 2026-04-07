package ru.shmelev.vpndetector.data.model

import kotlinx.serialization.Serializable
import ru.shmelev.vpndetector.detect.Check
import ru.shmelev.vpndetector.detect.Verdict

@Serializable
data class RunResult(
    val timestamp: Long,
    val tag: String = "",
    val checks: List<Check>,
    val verdict: Verdict,
)
