package ru.shmelev.vpndetector.ui.tabs

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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
    var selected by remember { mutableStateOf<Check?>(null) }
    val items = run.checks.filter { it.category == category }
    LazyColumn(Modifier.fillMaxSize().padding(8.dp)) {
        items(items, key = { it.id }) { c ->
            CheckRow(c) { selected = c }
        }
    }
    selected?.let { c ->
        CheckDetailDialog(c) { selected = null }
    }
}

@Composable
private fun CheckRow(c: Check, onClick: () -> Unit) {
    val (bg, label) = severityStyle(c.severity)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = bg),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("[$label] ${c.label}", fontWeight = FontWeight.Bold)
            Text(c.value, maxLines = 2)
        }
    }
}

@Composable
private fun CheckDetailDialog(c: Check, onDismiss: () -> Unit) {
    val (_, label) = severityStyle(c.severity)
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
        title = { Text("[$label] ${c.label}") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                LabelledBlock("ID", c.id)
                LabelledBlock("Category", c.category.name)
                LabelledBlock("Severity", c.severity.name)
                LabelledBlock("Value", c.value)
                LabelledBlock("Explanation", c.explanation)
            }
        },
    )
}

@Composable
private fun LabelledBlock(label: String, value: String) {
    Text(label, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
    Text(value)
}

private fun severityStyle(s: Severity): Pair<Color, String> = when (s) {
    Severity.HARD -> Color(0xFFFFCDD2) to "FAIL"
    Severity.SOFT -> Color(0xFFFFE0B2) to "WARN"
    Severity.PASS -> Color(0xFFC8E6C9) to "PASS"
    Severity.INFO -> Color(0xFFE0E0E0) to "INFO"
}
