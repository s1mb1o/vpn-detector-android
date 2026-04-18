package net.vpndetector.ui.verdict

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import net.vpndetector.R
import net.vpndetector.detect.MatrixLabel
import net.vpndetector.detect.Verdict
import net.vpndetector.detect.VerdictLevel

@Composable
fun VerdictBar(v: Verdict?, onShare: (() -> Unit)? = null) {
    val (color, label) = when (v?.level) {
        VerdictLevel.CLEAN -> Color(0xFF1B5E20) to stringResource(R.string.verdict_clean)
        VerdictLevel.SUSPICIOUS -> Color(0xFFE65100) to stringResource(R.string.verdict_suspicious)
        VerdictLevel.DETECTED -> Color(0xFFB71C1C) to stringResource(R.string.verdict_detected)
        null -> Color(0xFF424242) to stringResource(R.string.ui_verdict_no_run)
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(color)
            .windowInsetsPadding(WindowInsets.statusBars)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, color = Color.White, fontWeight = FontWeight.Bold)
            if (v != null) {
                Text(
                    stringResource(R.string.ui_verdict_score, v.score, v.hardCount, v.softCount),
                    color = Color.White,
                )
                Text(
                    stringResource(
                        R.string.ui_verdict_matrix,
                        matrixLabelText(v.matrix),
                        v.matrixGeoip.short(),
                        v.matrixDirect.short(),
                        v.matrixIndirect.short(),
                    ),
                    color = Color.White,
                )
            } else {
                Text(stringResource(R.string.ui_verdict_tap_to_start), color = Color.White)
            }
        }
        if (v != null && onShare != null) {
            IconButton(onClick = onShare) {
                Icon(
                    Icons.Filled.Share,
                    contentDescription = stringResource(R.string.ui_share_results_cd),
                    tint = Color.White,
                )
            }
        }
    }
}

@Composable
private fun matrixLabelText(m: MatrixLabel): String = when (m) {
    MatrixLabel.BYPASS_NOT_DETECTED -> stringResource(R.string.matrix_bypass_not_detected)
    MatrixLabel.NEEDS_REVIEW -> stringResource(R.string.matrix_needs_review)
    MatrixLabel.BYPASS_DETECTED -> stringResource(R.string.matrix_bypass_detected)
}

@Composable
private fun Boolean.short(): String =
    if (this) stringResource(R.string.ui_verdict_axis_yes) else stringResource(R.string.ui_verdict_axis_no)
