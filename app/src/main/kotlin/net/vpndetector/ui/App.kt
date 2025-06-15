package net.vpndetector.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cable
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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import net.vpndetector.detect.Category
import net.vpndetector.ui.tabs.CategoryTab
import net.vpndetector.ui.verdict.VerdictBar

private data class Tab(val route: String, val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector)

private val TABS = listOf(
    Tab("system", "System", Icons.Filled.Router),
    Tab("geoip", "GeoIP", Icons.Filled.Public),
    Tab("consistency", "Consistency", Icons.Filled.SwapHoriz),
    Tab("probes", "Probes", Icons.Filled.Sensors),
)

@Composable
fun App(vm: AppViewModel = viewModel()) {
    val nav = rememberNavController()
    val backStack by nav.currentBackStackEntryAsState()
    val checks by vm.checks.collectAsStateWithLifecycle()
    val verdict by vm.verdict.collectAsStateWithLifecycle()
    val running by vm.running.collectAsStateWithLifecycle()

    Scaffold(
        topBar = { VerdictBar(verdict) },
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
                composable("system") { CategoryTab(checks, Category.SYSTEM) }
                composable("geoip") { CategoryTab(checks, Category.GEOIP) }
                composable("consistency") { CategoryTab(checks, Category.CONSISTENCY) }
                composable("probes") { CategoryTab(checks, Category.PROBES) }
            }
        }
    }
}
