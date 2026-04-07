package ru.shmelev.vpndetector.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.launch
import ru.shmelev.vpndetector.data.RunRepository
import ru.shmelev.vpndetector.data.model.RunResult
import ru.shmelev.vpndetector.detect.DetectorEngine

class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val repo = RunRepository(app)

    private val _current = MutableStateFlow<RunResult?>(null)
    val current: StateFlow<RunResult?> = _current.asStateFlow()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    val history: StateFlow<List<RunResult>> = repo.history
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    fun runAll(tag: String = "") {
        if (_running.value) return
        viewModelScope.launch {
            _running.value = true
            try {
                val result = DetectorEngine.runAll(getApplication(), tag)
                _current.value = result
                repo.add(result)
            } finally {
                _running.value = false
            }
        }
    }

    fun clearHistory() {
        viewModelScope.launch { repo.clear() }
    }
}
