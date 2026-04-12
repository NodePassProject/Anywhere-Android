package com.argsment.anywhere.ui.navigation

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.vectorResource
import androidx.navigation.NavDestination.Companion.hasRoute
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.argsment.anywhere.R
import com.argsment.anywhere.ui.home.HomeScreen
import com.argsment.anywhere.ui.proxy.ChainListScreen
import com.argsment.anywhere.ui.proxy.ProxyListScreen
import com.argsment.anywhere.ui.settings.SettingsScreen
import com.argsment.anywhere.viewmodel.VpnViewModel
import kotlinx.serialization.Serializable

// Navigation routes
@Serializable object HomeRoute
@Serializable object ProxiesRoute
@Serializable object ChainsRoute
@Serializable object SettingsRoute

data class TopLevelRoute(
    val titleResId: Int,
    val route: Any,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

@Composable
fun AppNavigation(viewModel: VpnViewModel) {
    val navController = rememberNavController()

    // Switch to the Proxies tab when a deep link arrives so ProxyListScreen can consume it.
    val pendingDeepLink by viewModel.pendingDeepLinkUrl.collectAsState()
    LaunchedEffect(pendingDeepLink) {
        if (pendingDeepLink != null) {
            navController.navigate(ProxiesRoute) {
                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                launchSingleTop = true
                restoreState = true
            }
        }
    }

    val topLevelRoutes = listOf(
        TopLevelRoute(
            titleResId = R.string.home,
            route = HomeRoute,
            selectedIcon = Icons.Filled.Home,
            unselectedIcon = Icons.Outlined.Home
        ),
        TopLevelRoute(
            titleResId = R.string.proxies,
            route = ProxiesRoute,
            selectedIcon = ImageVector.vectorResource(R.drawable.ic_network_filled),
            unselectedIcon = ImageVector.vectorResource(R.drawable.ic_network_outlined)
        ),
        TopLevelRoute(
            titleResId = R.string.chains,
            route = ChainsRoute,
            selectedIcon = Icons.Filled.Link,
            unselectedIcon = Icons.Filled.Link
        ),
        TopLevelRoute(
            titleResId = R.string.settings,
            route = SettingsRoute,
            selectedIcon = Icons.Filled.Settings,
            unselectedIcon = Icons.Outlined.Settings
        )
    )

    Scaffold(
        bottomBar = {
            val navBackStackEntry by navController.currentBackStackEntryAsState()
            val currentDestination = navBackStackEntry?.destination

            NavigationBar {
                topLevelRoutes.forEach { topLevelRoute ->
                    val selected = currentDestination?.hierarchy?.any {
                        it.hasRoute(topLevelRoute.route::class)
                    } == true

                    NavigationBarItem(
                        icon = {
                            Icon(
                                imageVector = if (selected) topLevelRoute.selectedIcon else topLevelRoute.unselectedIcon,
                                contentDescription = stringResource(topLevelRoute.titleResId)
                            )
                        },
                        label = { Text(stringResource(topLevelRoute.titleResId)) },
                        selected = selected,
                        onClick = {
                            navController.navigate(topLevelRoute.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = HomeRoute
        ) {
            composable<HomeRoute> {
                HomeScreen(viewModel = viewModel, contentPadding = innerPadding)
            }
            composable<ProxiesRoute> {
                Box(modifier = Modifier.padding(innerPadding)) {
                    ProxyListScreen(viewModel = viewModel)
                }
            }
            composable<ChainsRoute> {
                Box(modifier = Modifier.padding(innerPadding)) {
                    ChainListScreen(viewModel = viewModel)
                }
            }
            composable<SettingsRoute> {
                Box(modifier = Modifier.padding(innerPadding)) {
                    SettingsScreen(viewModel = viewModel)
                }
            }
        }
    }
}
