package ru.shmelev.vpndetector.ui.verdict

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import ru.shmelev.vpndetector.detect.Verdict
import ru.shmelev.vpndetector.detect.VerdictLevel

@Composable
fun VerdictBar(v: Verdict?) {
    val (color, label) = when (v?.level) {
        VerdictLevel.CLEAN -> Color(0xFF1B5E20) to "CLEAN"
        VerdictLevel.SUSPICIOUS -> Color(0xFFE65100) to "SUSPICIOUS"
        VerdictLevel.DETECTED -> Color(0xFFB71C1C) to "DETECTED"
        null -> Color(0xFF424242) to "— no run yet —"
    }
    Column(
        Modifier.fillMaxWidth().background(color).padding(16.dp)
    ) {
        Text(label, color = Color.White, fontWeight = FontWeight.Bold)
        if (v != null) {
            Text(
                "score=${v.score}  hard=${v.hardCount}  soft=${v.softCount}",
                color = Color.White,
            )
        } else {
            Text("Tap “Run all checks” to start.", color = Color.White)
        }
    }
}
