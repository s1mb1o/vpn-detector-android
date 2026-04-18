package net.vpndetector.ui.tabs

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import net.vpndetector.R
import net.vpndetector.data.model.RunResult
import net.vpndetector.detect.Category
import net.vpndetector.detect.Check
import net.vpndetector.detect.DetailEntry
import net.vpndetector.detect.Severity
import net.vpndetector.detect.VerdictLevel

@Composable
fun CategoryTab(run: RunResult?, category: Category) {
    if (run == null) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text(stringResource(R.string.ui_tab_no_run))
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
    selected?.let { c -> CheckDetailDialog(c) { selected = null } }
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
            Text(c.value)
            Text(c.explanation, fontWeight = FontWeight.Light)
        }
    }
}

@Composable
private fun CheckDetailDialog(c: Check, onDismiss: () -> Unit) {
    val (_, label) = severityStyle(c.severity)
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.ui_dialog_close)) } },
        title = { Text("[$label] ${c.label}") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                LabelledBlock(stringResource(R.string.ui_dialog_id), c.id)
                LabelledBlock(stringResource(R.string.ui_dialog_category), categoryText(c.category))
                LabelledBlock(stringResource(R.string.ui_dialog_severity), c.severity.name)
                LabelledBlock(stringResource(R.string.ui_dialog_value), c.value)
                LabelledBlock(stringResource(R.string.ui_dialog_explanation), c.explanation)
                if (c.details.isNotEmpty()) {
                    Spacer(Modifier.padding(top = 12.dp))
                    Text(stringResource(R.string.ui_dialog_details), fontWeight = FontWeight.Bold)
                    HorizontalDivider(Modifier.padding(vertical = 4.dp))
                    c.details.forEach { DetailRow(it) }
                }
            }
        },
    )
}

@Composable
private fun DetailRow(d: DetailEntry) {
    val (bg, label) = severityStyle(d.verdict)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp)
            .background(bg, RoundedCornerShape(4.dp))
            .padding(8.dp),
    ) {
        Text(
            text = "[$label]",
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp,
        )
        Spacer(Modifier.width(6.dp))
        Column(Modifier.fillMaxWidth()) {
            Text(d.source, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Text(d.reported, fontSize = 13.sp)
        }
    }
}

@Composable
private fun LabelledBlock(label: String, value: String) {
    Text(label, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
    Text(value)
}

@Composable
private fun severityStyle(s: Severity): Pair<Color, String> = when (s) {
    Severity.HARD -> Color(0xFFFFCDD2) to stringResource(R.string.severity_fail)
    Severity.SOFT -> Color(0xFFFFE0B2) to stringResource(R.string.severity_warn)
    Severity.PASS -> Color(0xFFC8E6C9) to stringResource(R.string.severity_pass)
    Severity.INFO -> Color(0xFFE0E0E0) to stringResource(R.string.severity_info)
}

@Composable
private fun categoryText(c: Category): String = when (c) {
    Category.SYSTEM -> stringResource(R.string.category_system)
    Category.GEOIP -> stringResource(R.string.category_geoip)
    Category.CONSISTENCY -> stringResource(R.string.category_consistency)
    Category.PROBES -> stringResource(R.string.category_probes)
}

@Composable
fun verdictLevelText(v: VerdictLevel): String = when (v) {
    VerdictLevel.CLEAN -> stringResource(R.string.verdict_clean)
    VerdictLevel.SUSPICIOUS -> stringResource(R.string.verdict_suspicious)
    VerdictLevel.DETECTED -> stringResource(R.string.verdict_detected)
}
