package com.argsment.anywhere.ui.proxy

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.data.model.ProxyChain
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.network.LatencyResult
import com.argsment.anywhere.ui.components.LatencyBadge
import com.argsment.anywhere.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChainListScreen(viewModel: VpnViewModel) {
    val chains by viewModel.chainRepository.chains.collectAsState()
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()
    val selectedChainId by viewModel.selectedChainId.collectAsState()
    val chainLatencyResults by viewModel.chainLatencyResults.collectAsState()

    var showingAddSheet by remember { mutableStateOf(false) }
    var showingNotEnoughProxiesAlert by remember { mutableStateOf(false) }
    var chainToEdit by remember { mutableStateOf<ProxyChain?>(null) }
    var chainToDelete by remember { mutableStateOf<ProxyChain?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.chains)) },
                actions = {
                    if (chains.isNotEmpty()) {
                        IconButton(onClick = { viewModel.testAllChainLatencies() }) {
                            Icon(
                                imageVector = Icons.Default.Speed,
                                contentDescription = stringResource(R.string.test_all)
                            )
                        }
                    }
                    IconButton(onClick = {
                        if (configurations.size < 2) {
                            showingNotEnoughProxiesAlert = true
                        } else {
                            showingAddSheet = true
                        }
                    }) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = stringResource(R.string.add)
                        )
                    }
                }
            )
        }
    ) { innerPadding ->
        if (chains.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = stringResource(R.string.no_chains),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = stringResource(R.string.tap_to_add_chain),
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
                items(chains, key = { it.id }) { chain ->
                    ChainRow(
                        chain = chain,
                        configurations = configurations,
                        isSelected = selectedChainId == chain.id,
                        latency = chainLatencyResults[chain.id],
                        onSelect = { viewModel.selectChain(chain) },
                        onEdit = { chainToEdit = chain },
                        onDelete = { chainToDelete = chain },
                        onTestLatency = { viewModel.testChainLatency(chain) }
                    )
                }
            }
        }
    }

    if (showingAddSheet) {
        ModalBottomSheet(
            onDismissRequest = { showingAddSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ) {
            ChainEditorScreen(
                chain = null,
                configurations = configurations,
                subscriptions = subscriptions,
                onSave = { chain ->
                    viewModel.addChain(chain)
                    showingAddSheet = false
                },
                onDismiss = { showingAddSheet = false }
            )
        }
    }

    chainToEdit?.let { chain ->
        ModalBottomSheet(
            onDismissRequest = { chainToEdit = null },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ) {
            ChainEditorScreen(
                chain = chain,
                configurations = configurations,
                subscriptions = subscriptions,
                onSave = { updated ->
                    viewModel.updateChain(updated)
                    chainToEdit = null
                },
                onDismiss = { chainToEdit = null }
            )
        }
    }

    chainToDelete?.let { chain ->
        AlertDialog(
            onDismissRequest = { chainToDelete = null },
            title = { Text(stringResource(R.string.delete)) },
            text = { Text(chain.name) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.deleteChain(chain)
                    chainToDelete = null
                }) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { chainToDelete = null }) { Text(stringResource(R.string.cancel)) }
            }
        )
    }

    if (showingNotEnoughProxiesAlert) {
        AlertDialog(
            onDismissRequest = { showingNotEnoughProxiesAlert = false },
            title = { Text(stringResource(R.string.not_enough_proxies)) },
            text = { Text(stringResource(R.string.not_enough_proxies_message)) },
            confirmButton = {
                TextButton(onClick = { showingNotEnoughProxiesAlert = false }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ChainRow(
    chain: ProxyChain,
    configurations: List<ProxyConfiguration>,
    isSelected: Boolean,
    latency: LatencyResult?,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onTestLatency: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }

    val proxies = remember(chain.proxyIds, configurations) {
        chain.proxyIds.mapNotNull { id -> configurations.find { it.id == id } }
    }
    val isValid = proxies.size == chain.proxyIds.size && proxies.size >= 2

    Box {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .combinedClickable(
                    onClick = { if (isValid) onSelect() },
                    onLongClick = { showMenu = true }
                )
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = chain.name,
                        style = MaterialTheme.typography.bodyLarge,
                        color = if (isValid) MaterialTheme.colorScheme.onSurface
                        else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                    )
                    if (isSelected) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "\u2713",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }

                if (isValid) {
                    Text(
                        text = proxies.joinToString(" \u2192 ") { it.name },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1
                    )
                } else {
                    Text(
                        text = stringResource(R.string.invalid_chain),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }

                Row {
                    Text(
                        text = stringResource(R.string.n_proxies, proxies.size),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                    )
                    if (proxies.size >= 2) {
                        Text(
                            text = " \u00B7 ${proxies.first().serverAddress} \u2192 ${proxies.last().serverAddress}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                            maxLines = 1
                        )
                    }
                }
            }

            if (isValid) {
                // Tap latency to re-test this single chain — mirrors iOS ChainListView.
                Box(
                    modifier = Modifier.clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null,
                        onClick = onTestLatency
                    )
                ) {
                    LatencyBadge(latency = latency)
                }
            }
        }

        DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
            if (isValid) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.test_latency)) },
                    leadingIcon = { Icon(Icons.Default.Speed, contentDescription = null) },
                    onClick = {
                        showMenu = false
                        onTestLatency()
                    }
                )
            }
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
