package com.argsment.anywhere.ui.proxy

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.data.model.Subscription
import com.argsment.anywhere.data.model.VlessConfiguration
import com.argsment.anywhere.ui.components.ProxyCardContent
import com.argsment.anywhere.viewmodel.VpnViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ProxyListScreen(viewModel: VpnViewModel) {
    val context = LocalContext.current
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()
    val selectedConfigId by viewModel.selectedConfigId.collectAsState()
    val latencyResults by viewModel.latencyResults.collectAsState()

    var showingAddSheet by remember { mutableStateOf(false) }
    var showingManualAddSheet by remember { mutableStateOf(false) }
    var configurationToEdit by remember { mutableStateOf<VlessConfiguration?>(null) }
    var updatingSubscriptionId by remember { mutableStateOf<java.util.UUID?>(null) }
    var showSubscriptionError by remember { mutableStateOf(false) }
    var subscriptionErrorMessage by remember { mutableStateOf("") }

    val scope = rememberCoroutineScope()

    val standaloneConfigs = remember(configurations) {
        configurations.filter { it.subscriptionId == null }
    }

    val subscribedGroups = remember(configurations, subscriptions) {
        subscriptions.mapNotNull { subscription ->
            val configs = configurations.filter { it.subscriptionId == subscription.id }
            if (configs.isEmpty()) null else subscription to configs
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.proxies)) },
                actions = {
                    IconButton(onClick = { viewModel.testAllLatencies() }) {
                        Icon(
                            imageVector = Icons.Default.Speed,
                            contentDescription = stringResource(R.string.test_all)
                        )
                    }
                    IconButton(onClick = { showingAddSheet = true }) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = stringResource(R.string.add)
                        )
                    }
                }
            )
        }
    ) { innerPadding ->
        if (configurations.isEmpty()) {
            // Empty state
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = stringResource(R.string.no_proxies),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = stringResource(R.string.tap_to_add_proxy),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                // Standalone configurations
                if (standaloneConfigs.isNotEmpty()) {
                    items(standaloneConfigs, key = { it.id }) { config ->
                        ConfigurationRow(
                            configuration = config,
                            isSelected = config.id == selectedConfigId,
                            latency = latencyResults[config.id],
                            onSelect = { viewModel.setSelectedConfiguration(config) },
                            onEdit = { configurationToEdit = config },
                            onDelete = { viewModel.deleteConfiguration(config) },
                            onTestLatency = { viewModel.testLatency(forConfig = config) }
                        )
                    }
                }

                // Subscription groups
                subscribedGroups.forEach { (subscription, configs) ->
                    item(key = "header_${subscription.id}") {
                        SubscriptionHeader(
                            subscription = subscription,
                            isUpdating = updatingSubscriptionId == subscription.id,
                            onUpdate = {
                                if (updatingSubscriptionId == null) {
                                    updatingSubscriptionId = subscription.id
                                    scope.launch {
                                        try {
                                            viewModel.updateSubscription(subscription)
                                        } catch (e: Exception) {
                                            subscriptionErrorMessage = e.message ?: context.getString(R.string.unknown_error)
                                            showSubscriptionError = true
                                        }
                                        updatingSubscriptionId = null
                                    }
                                }
                            },
                            onDelete = { viewModel.deleteSubscription(subscription) }
                        )
                    }
                    items(configs, key = { it.id }) { config ->
                        ConfigurationRow(
                            configuration = config,
                            isSelected = config.id == selectedConfigId,
                            latency = latencyResults[config.id],
                            onSelect = { viewModel.setSelectedConfiguration(config) },
                            onEdit = { configurationToEdit = config },
                            onDelete = { viewModel.deleteConfiguration(config) },
                            onTestLatency = { viewModel.testLatency(forConfig = config) }
                        )
                    }
                }
            }
        }
    }

    // Add proxy bottom sheet
    if (showingAddSheet) {
        ModalBottomSheet(
            onDismissRequest = { showingAddSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ) {
            AddProxyScreen(
                onDismiss = { showingAddSheet = false },
                onShowManualAdd = {
                    showingAddSheet = false
                    showingManualAddSheet = true
                },
                onImport = { config ->
                    viewModel.addConfiguration(config)
                    showingAddSheet = false
                },
                onSubscriptionImport = { configs, subscription ->
                    viewModel.addSubscription(configs, subscription)
                    showingAddSheet = false
                }
            )
        }
    }

    // Manual add sheet
    if (showingManualAddSheet) {
        ModalBottomSheet(
            onDismissRequest = { showingManualAddSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ) {
            ProxyEditorScreen(
                configuration = null,
                onSave = { config ->
                    viewModel.addConfiguration(config)
                    showingManualAddSheet = false
                },
                onDismiss = { showingManualAddSheet = false }
            )
        }
    }

    // Edit sheet
    configurationToEdit?.let { config ->
        ModalBottomSheet(
            onDismissRequest = { configurationToEdit = null },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ) {
            ProxyEditorScreen(
                configuration = config,
                onSave = { updated ->
                    viewModel.updateConfiguration(updated)
                    configurationToEdit = null
                },
                onDismiss = { configurationToEdit = null }
            )
        }
    }

    // Subscription error dialog
    if (showSubscriptionError) {
        AlertDialog(
            onDismissRequest = { showSubscriptionError = false },
            title = { Text(stringResource(R.string.update_failed)) },
            text = { Text(subscriptionErrorMessage) },
            confirmButton = {
                TextButton(onClick = { showSubscriptionError = false }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}

@Composable
private fun SubscriptionHeader(
    subscription: Subscription,
    isUpdating: Boolean,
    onUpdate: () -> Unit,
    onDelete: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = subscription.name,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.weight(1f)
        )

        if (isUpdating) {
            CircularProgressIndicator(
                modifier = Modifier.size(16.dp),
                strokeWidth = 2.dp
            )
        } else {
            IconButton(onClick = onUpdate, modifier = Modifier.size(32.dp)) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = stringResource(R.string.update),
                    modifier = Modifier.size(18.dp)
                )
            }
        }

        Box {
            IconButton(onClick = { showMenu = true }, modifier = Modifier.size(32.dp)) {
                Icon(
                    imageVector = Icons.Default.MoreVert,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
            }
            DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.update)) },
                    onClick = {
                        showMenu = false
                        onUpdate()
                    },
                    leadingIcon = { Icon(Icons.Default.Refresh, contentDescription = null) }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) },
                    onClick = {
                        showMenu = false
                        onDelete()
                    },
                    leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error) }
                )
            }
        }
    }
    HorizontalDivider(modifier = Modifier.padding(horizontal = 16.dp))
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ConfigurationRow(
    configuration: VlessConfiguration,
    isSelected: Boolean,
    latency: com.argsment.anywhere.data.network.LatencyResult?,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onTestLatency: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }

    Box {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .combinedClickable(
                    onClick = onSelect,
                    onLongClick = { showMenu = true }
                )
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            ProxyCardContent(
                configuration = configuration,
                isSelected = isSelected,
                latency = latency,
                modifier = Modifier.weight(1f)
            )
        }

        DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.test_latency)) },
                leadingIcon = { Icon(Icons.Default.Speed, contentDescription = null) },
                onClick = {
                    showMenu = false
                    onTestLatency()
                }
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.edit)) },
                onClick = {
                    showMenu = false
                    onEdit()
                },
                leadingIcon = { Icon(Icons.Default.Edit, contentDescription = null) }
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) },
                onClick = {
                    showMenu = false
                    onDelete()
                },
                leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error) }
            )
        }
    }
}
