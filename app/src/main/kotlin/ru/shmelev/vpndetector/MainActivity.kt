package ru.shmelev.vpndetector

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.core.content.ContextCompat
import ru.shmelev.vpndetector.ui.App

class MainActivity : ComponentActivity() {

    private val permissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { /* ignore */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Only ask once: skip if already granted, and skip on configuration-change recreations
        // (savedInstanceState != null) so we don't re-prompt on rotation.
        if (savedInstanceState == null) {
            val needed = listOf(Manifest.permission.ACCESS_FINE_LOCATION)
                .filter {
                    ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
                }
            if (needed.isNotEmpty()) {
                permissionLauncher.launch(needed.toTypedArray())
            }
        }

        setContent {
            MaterialTheme {
                Surface { App() }
            }
        }
    }
}
