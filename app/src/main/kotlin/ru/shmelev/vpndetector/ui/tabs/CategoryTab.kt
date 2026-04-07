package ru.shmelev.vpndetector.ui.tabs

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import ru.shmelev.vpndetector.data.model.RunResult
import ru.shmelev.vpndetector.detect.Category
import ru.shmelev.vpndetector.detect.Check
import ru.shmelev.vpndetector.detect.Severity

@Composable
fun CategoryTab(run: RunResult?, category: Category) {
    if (run == null) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("No run yet")
        }
        return
    }
    val items = run.checks.filter { it.category == category }
    LazyColumn(Modifier.fillMaxSize().padding(8.dp)) {
        items(items, key = { it.id }) { CheckRow(it) }
    }
}

@Composable
private fun CheckRow(c: Check) {
    val (bg, label) = when (c.severity) {
        Severity.HARD -> Color(0xFFFFCDD2) to "FAIL"
        Severity.SOFT -> Color(0xFFFFE0B2) to "WARN"
        Severity.PASS -> Color(0xFFC8E6C9) to "PASS"
        Severity.INFO -> Color(0xFFE0E0E0) to "INFO"
    }
    Card(
        modifier = Modifier.fillMaxSize().padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = bg),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("[$label] ${c.label}", fontWeight = FontWeight.Bold)
            Text(c.value)
            Text(c.explanation, fontWeight = FontWeight.Light)
        }
    }
}
