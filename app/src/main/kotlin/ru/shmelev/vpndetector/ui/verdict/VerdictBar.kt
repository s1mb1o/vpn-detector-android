package ru.shmelev.vpndetector.ui.verdict

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import ru.shmelev.vpndetector.detect.Verdict
import ru.shmelev.vpndetector.detect.VerdictLevel

@Composable
fun VerdictBar(v: Verdict?, onShare: (() -> Unit)? = null) {
    val (color, label) = when (v?.level) {
        VerdictLevel.CLEAN -> Color(0xFF1B5E20) to "CLEAN"
        VerdictLevel.SUSPICIOUS -> Color(0xFFE65100) to "SUSPICIOUS"
        VerdictLevel.DETECTED -> Color(0xFFB71C1C) to "DETECTED"
        null -> Color(0xFF424242) to "— no run yet —"
    }
    Row(
        modifier = Modifier.fillMaxWidth().background(color).padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
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
        if (v != null && onShare != null) {
            IconButton(onClick = onShare) {
                Icon(Icons.Filled.Share, contentDescription = "Share results", tint = Color.White)
            }
        }
    }
}
