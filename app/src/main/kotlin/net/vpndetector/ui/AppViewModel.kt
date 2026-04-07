package net.vpndetector.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.launch
import android.util.Log
import net.vpndetector.data.RunRepository
import net.vpndetector.data.model.RunResult
import net.vpndetector.detect.DetectorEngine
import net.vpndetector.detect.Severity

class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val repo = RunRepository(app)

    private val _current = MutableStateFlow<RunResult?>(null)
    val current: StateFlow<RunResult?> = _current.asStateFlow()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    val history: StateFlow<List<RunResult>> = repo.history
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun runAll(tag: String = "") {
        if (_running.value) return
        viewModelScope.launch {
            _running.value = true
            _error.value = null
            try {
                val previous = repo.snapshot().firstOrNull()
                val result = DetectorEngine.runAll(getApplication(), tag, previous)
                _current.value = result
                repo.add(result)
                logRun(result)
            } catch (e: Throwable) {
                Log.e(LOG_TAG, "runAll failed", e)
                _error.value = e.message ?: e.javaClass.simpleName
            } finally {
                _running.value = false
            }
        }
    }

    fun clearHistory() {
        viewModelScope.launch { repo.clear() }
    }

    /** Dump every check + per-source detail to logcat under tag VpnDetector. */
    private fun logRun(r: RunResult) {
        Log.i(LOG_TAG, "===== run ts=${r.timestamp} verdict=${r.verdict.level} " +
            "score=${r.verdict.score} hard=${r.verdict.hardCount} soft=${r.verdict.softCount} " +
            "matrix=${r.verdict.matrix}(geoip=${r.verdict.matrixGeoip} " +
            "direct=${r.verdict.matrixDirect} indirect=${r.verdict.matrixIndirect}) =====")
        for (c in r.checks) {
            Log.i(LOG_TAG, "[${c.severity.short()}] ${c.category}/${c.id}: ${c.label} = ${c.value}")
            for (d in c.details) {
                Log.i(LOG_TAG, "    [${d.verdict.short()}] ${d.source} -> ${d.reported}")
            }
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
