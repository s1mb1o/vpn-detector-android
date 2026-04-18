package net.vpndetector.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cable
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.SwapHoriz
import android.content.Intent
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import net.vpndetector.R
import net.vpndetector.detect.Category
import net.vpndetector.detect.VerdictLevel
import net.vpndetector.ui.history.HistoryScreen
import net.vpndetector.ui.tabs.CategoryTab
import net.vpndetector.ui.verdict.VerdictBar

private data class Tab(val route: String, val labelRes: Int, val icon: androidx.compose.ui.graphics.vector.ImageVector)

private val TABS = listOf(
    Tab("system", R.string.ui_tab_system, Icons.Filled.Router),
    Tab("geoip", R.string.ui_tab_geoip, Icons.Filled.Public),
    Tab("consistency", R.string.ui_tab_consistency, Icons.Filled.SwapHoriz),
    Tab("probes", R.string.ui_tab_probes, Icons.Filled.Sensors),
    Tab("history", R.string.ui_tab_history, Icons.Filled.History),
)

@Composable
fun App(vm: AppViewModel = viewModel()) {
    val nav = rememberNavController()
    val backStack by nav.currentBackStackEntryAsState()
    val current by vm.current.collectAsStateWithLifecycle()
    val running by vm.running.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val shareSubjectFormat = stringResource(R.string.ui_share_subject)
    val shareChooserTitle = stringResource(R.string.ui_share_chooser_title)
    val runText = stringResource(R.string.ui_fab_run)
    val runningText = stringResource(R.string.ui_fab_running)
    val verdictTexts = mapOf(
        VerdictLevel.CLEAN to stringResource(R.string.verdict_clean),
        VerdictLevel.SUSPICIOUS to stringResource(R.string.verdict_suspicious),
        VerdictLevel.DETECTED to stringResource(R.string.verdict_detected),
    )

    Scaffold(
        topBar = {
            VerdictBar(
                v = current?.verdict,
                onShare = current?.let { run ->
                    {
                        val send = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(
                                Intent.EXTRA_SUBJECT,
                                String.format(shareSubjectFormat, verdictTexts[run.verdict.level] ?: ""),
                            )
                            putExtra(Intent.EXTRA_TEXT, run.toShareText())
                        }
                        ctx.startActivity(Intent.createChooser(send, shareChooserTitle))
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                TABS.forEach { tab ->
                    val label = stringResource(tab.labelRes)
                    val selected = backStack?.destination?.route == tab.route
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            nav.navigate(tab.route) {
                                popUpTo(nav.graph.startDestinationId) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = { Icon(tab.icon, contentDescription = label) },
                        label = { Text(label) },
                    )
                }
            }
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { vm.runAll() },
                icon = { Icon(if (running) Icons.Filled.Cable else Icons.Filled.Refresh, null) },
                text = { Text(if (running) runningText else runText) },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            NavHost(navController = nav, startDestination = "system") {
                composable("system") { CategoryTab(current, Category.SYSTEM) }
                composable("geoip") { CategoryTab(current, Category.GEOIP) }
                composable("consistency") { CategoryTab(current, Category.CONSISTENCY) }
                composable("probes") { CategoryTab(current, Category.PROBES) }
                composable("history") { HistoryScreen(vm) }
            }
        }
    }
}
