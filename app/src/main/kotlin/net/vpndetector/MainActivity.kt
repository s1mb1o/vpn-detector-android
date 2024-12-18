package net.vpndetector

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
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
import net.vpndetector.detect.Check
import net.vpndetector.detect.Severity
import net.vpndetector.detect.SystemChecks
import net.vpndetector.detect.Verdict
import net.vpndetector.detect.VerdictAggregator
import net.vpndetector.detect.VerdictLevel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface {
                    var checks by remember { mutableStateOf<List<Check>>(emptyList()) }
                    var verdict by remember { mutableStateOf<Verdict?>(null) }
                    Column(Modifier.fillMaxSize()) {
                        VerdictBar(verdict)
                        Button(
                            onClick = {
                                checks = SystemChecks.run(this@MainActivity)
                                verdict = VerdictAggregator.aggregate(checks)
                            },
                            modifier = Modifier.align(Alignment.CenterHorizontally).padding(8.dp),
                        ) {
                            Text("Run checks")
                        }
                        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 8.dp)) {
                            items(checks, key = { it.id }) { c ->
                                CheckRow(c)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun VerdictBar(v: Verdict?) {
    val (color, label) = when (v?.level) {
        VerdictLevel.CLEAN -> Color(0xFF1B5E20) to "CLEAN"
        VerdictLevel.SUSPICIOUS -> Color(0xFFE65100) to "SUSPICIOUS"
        VerdictLevel.DETECTED -> Color(0xFFB71C1C) to "DETECTED"
        null -> Color(0xFF424242) to "— no run yet —"
    }
    Column(
        Modifier.fillMaxWidth().background(color).padding(16.dp),
    ) {
        Text(label, color = Color.White, fontWeight = FontWeight.Bold)
        if (v != null) {
            Text(
                "score=${v.score}  hard=${v.hardCount}  soft=${v.softCount}",
                color = Color.White,
            )
        } else {
            Text("Tap \"Run checks\" to start.", color = Color.White)
        }
    }
}

@Composable
private fun CheckRow(c: Check) {
    val bg = when (c.severity) {
        Severity.HARD -> Color(0xFFFFCDD2)
        Severity.SOFT -> Color(0xFFFFE0B2)
        Severity.PASS -> Color(0xFFC8E6C9)
        Severity.INFO -> Color(0xFFE0E0E0)
    }
    val label = when (c.severity) {
        Severity.HARD -> "FAIL"
        Severity.SOFT -> "WARN"
        Severity.PASS -> "PASS"
        Severity.INFO -> "INFO"
    }
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = bg),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("[$label] ${c.label}", fontWeight = FontWeight.Bold)
            Text(c.value)
            Text(c.explanation, fontWeight = FontWeight.Light)
        }
    }
}
