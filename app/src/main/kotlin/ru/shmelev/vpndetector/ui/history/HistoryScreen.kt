package ru.shmelev.vpndetector.ui.history

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import ru.shmelev.vpndetector.ui.AppViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun HistoryScreen(vm: AppViewModel) {
    val history by vm.history.collectAsStateWithLifecycle()
    val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

    Column(Modifier.fillMaxSize().padding(8.dp)) {
        Button(onClick = { vm.clearHistory() }) { Text("Clear history") }
        LazyColumn(Modifier.fillMaxSize()) {
            items(history, key = { it.timestamp }) { run ->
                Card(Modifier.fillMaxSize().padding(vertical = 4.dp)) {
                    Column(Modifier.padding(12.dp)) {
                        Text("${fmt.format(Date(run.timestamp))}  •  ${run.verdict.level}")
                        Text("score=${run.verdict.score} hard=${run.verdict.hardCount} soft=${run.verdict.softCount}")
                        if (run.tag.isNotEmpty()) Text("tag: ${run.tag}")
                    }
                }
            }
        }
    }
}
