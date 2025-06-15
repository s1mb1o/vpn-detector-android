package net.vpndetector.ui

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import net.vpndetector.detect.Check
import net.vpndetector.detect.DetectorEngine
import net.vpndetector.detect.Severity
import net.vpndetector.detect.Verdict

class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val _checks = MutableStateFlow<List<Check>>(emptyList())
    val checks: StateFlow<List<Check>> = _checks.asStateFlow()

    private val _verdict = MutableStateFlow<Verdict?>(null)
    val verdict: StateFlow<Verdict?> = _verdict.asStateFlow()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    fun runAll() {
        if (_running.value) return
        viewModelScope.launch {
            _running.value = true
            try {
                val (checks, verdict) = DetectorEngine.runAll(getApplication())
                _checks.value = checks
                _verdict.value = verdict
                logRun(checks, verdict)
            } catch (e: Throwable) {
                Log.e(LOG_TAG, "runAll failed", e)
            } finally {
                _running.value = false
            }
        }
    }

    private fun logRun(checks: List<Check>, verdict: Verdict) {
        Log.i(LOG_TAG, "===== run verdict=${verdict.level} " +
            "score=${verdict.score} hard=${verdict.hardCount} soft=${verdict.softCount} =====")
        for (c in checks) {
            Log.i(LOG_TAG, "[${c.severity.short()}] ${c.category}/${c.id}: ${c.label} = ${c.value}")
        }
        Log.i(LOG_TAG, "===== end run =====")
    }

    private fun Severity.short(): String = when (this) {
        Severity.HARD -> "FAIL"
        Severity.SOFT -> "WARN"
        Severity.PASS -> "PASS"
        Severity.INFO -> "INFO"
    }

    private companion object { const val LOG_TAG = "VpnDetector" }
}
