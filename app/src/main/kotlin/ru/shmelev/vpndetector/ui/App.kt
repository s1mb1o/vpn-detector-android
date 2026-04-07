package ru.shmelev.vpndetector.ui

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
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import ru.shmelev.vpndetector.detect.Category
import ru.shmelev.vpndetector.ui.history.HistoryScreen
import ru.shmelev.vpndetector.ui.tabs.CategoryTab
import ru.shmelev.vpndetector.ui.verdict.VerdictBar

private data class Tab(val route: String, val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector)

private val TABS = listOf(
    Tab("system", "System", Icons.Filled.Router),
    Tab("geoip", "GeoIP", Icons.Filled.Public),
    Tab("consistency", "Consistency", Icons.Filled.SwapHoriz),
    Tab("probes", "Probes", Icons.Filled.Sensors),
    Tab("history", "History", Icons.Filled.History),
)

@Composable
fun App(vm: AppViewModel = viewModel()) {
    val nav = rememberNavController()
    val backStack by nav.currentBackStackEntryAsState()
    val current by vm.current.collectAsState()
    val running by vm.running.collectAsState()

    Scaffold(
        topBar = { VerdictBar(current?.verdict) },
        bottomBar = {
            NavigationBar {
                TABS.forEach { tab ->
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
                        icon = { Icon(tab.icon, contentDescription = tab.label) },
                        label = { Text(tab.label) },
                    )
                }
            }
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { vm.runAll() },
                icon = { Icon(if (running) Icons.Filled.Cable else Icons.Filled.Refresh, null) },
                text = { Text(if (running) "Running…" else "Run all checks") },
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
