package com.argsment.anywhere.ui.proxy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.data.model.ProxyChain
import com.argsment.anywhere.data.model.ProxyConfiguration
import java.util.UUID

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChainEditorScreen(
    chain: ProxyChain?,
    configurations: List<ProxyConfiguration>,
    onSave: (ProxyChain) -> Unit,
    onDismiss: () -> Unit
) {
    val isEditing = chain != null
    var name by remember { mutableStateOf(chain?.name ?: "") }
    val selectedProxyIds = remember { mutableStateListOf<UUID>().apply { chain?.proxyIds?.let { addAll(it) } } }
    var showingProxyPicker by remember { mutableStateOf(false) }

    val selectedProxies = remember(selectedProxyIds.toList(), configurations) {
        selectedProxyIds.mapNotNull { id -> configurations.find { it.id == id } }
    }

    val canSave = name.isNotBlank() && selectedProxies.size >= 2

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
    ) {
        // Header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
            Text(
                text = stringResource(if (isEditing) R.string.edit_chain else R.string.new_chain),
                style = MaterialTheme.typography.titleMedium
            )
            TextButton(
                onClick = {
                    val result = ProxyChain(
                        id = chain?.id ?: UUID.randomUUID(),
                        name = name.trim(),
                        proxyIds = selectedProxyIds.toList()
                    )
                    onSave(result)
                },
                enabled = canSave
            ) {
                Text(stringResource(R.string.save))
            }
        }

        HorizontalDivider()
        Spacer(modifier = Modifier.height(12.dp))

        // Name field
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text(stringResource(R.string.name)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Proxies section header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(R.string.proxies_in_chain),
                style = MaterialTheme.typography.titleSmall
            )
            IconButton(onClick = { showingProxyPicker = true }) {
                Icon(Icons.Default.Add, contentDescription = stringResource(R.string.add_proxy_to_chain))
            }
        }

        if (selectedProxies.size < 2) {
            Text(
                text = stringResource(R.string.chain_min_proxies),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                modifier = Modifier.padding(bottom = 8.dp)
            )
        }

        // Proxy list
        LazyColumn(
            modifier = Modifier.weight(1f, fill = false)
        ) {
            itemsIndexed(selectedProxies, key = { _, proxy -> proxy.id }) { index, proxy ->
                ProxyChainItem(
                    index = index,
                    proxy = proxy,
                    totalCount = selectedProxies.size,
                    onRemove = { selectedProxyIds.removeAt(index) }
                )
            }
        }

        // Route preview
        if (selectedProxies.size >= 2) {
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                text = stringResource(R.string.route_preview),
                style = MaterialTheme.typography.titleSmall
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "You \u2192 " + selectedProxies.joinToString(" \u2192 ") { it.name } + " \u2192 Target",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }

    // Proxy picker
    if (showingProxyPicker) {
        ModalBottomSheet(
            onDismissRequest = { showingProxyPicker = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ) {
            ProxyPickerScreen(
                configurations = configurations,
                excludedIds = selectedProxyIds.toSet(),
                onSelect = { proxy ->
                    selectedProxyIds.add(proxy.id)
                    showingProxyPicker = false
                },
                onDismiss = { showingProxyPicker = false }
            )
        }
    }
}

@Composable
private fun ProxyChainItem(
    index: Int,
    proxy: ProxyConfiguration,
    totalCount: Int,
    onRemove: () -> Unit
) {
    val badgeColor = when {
        index == 0 -> Color(0xFF2196F3) // blue - entry
        index == totalCount - 1 -> Color(0xFF4CAF50) // green - exit
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    val roleLabel = when {
        index == 0 -> stringResource(R.string.entry)
        index == totalCount - 1 -> stringResource(R.string.exit)
        else -> null
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Index badge
        Surface(
            shape = CircleShape,
            color = badgeColor,
            modifier = Modifier.size(24.dp)
        ) {
            Text(
                text = "${index + 1}",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = Color.White,
                modifier = Modifier.padding(4.dp)
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = proxy.name,
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                text = "${proxy.serverAddress}:${proxy.serverPort}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        if (roleLabel != null) {
            Text(
                text = roleLabel,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.width(4.dp))
        }

        IconButton(onClick = onRemove, modifier = Modifier.size(32.dp)) {
            Icon(
                imageVector = Icons.Default.Close,
                contentDescription = stringResource(R.string.delete),
                modifier = Modifier.size(18.dp)
            )
        }
    }
}

@Composable
private fun ProxyPickerScreen(
    configurations: List<ProxyConfiguration>,
    excludedIds: Set<UUID>,
    onSelect: (ProxyConfiguration) -> Unit,
    onDismiss: () -> Unit
) {
    val available = remember(configurations, excludedIds) {
        configurations.filter { it.id !in excludedIds }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
            Text(
                text = stringResource(R.string.select_proxy),
                style = MaterialTheme.typography.titleMedium
            )
            // Spacer for symmetry
            Spacer(modifier = Modifier.width(64.dp))
        }

        HorizontalDivider()

        if (available.isEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 32.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = stringResource(R.string.no_proxies_available),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = stringResource(R.string.all_proxies_in_chain),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            }
        } else {
            LazyColumn {
                items(available.size) { index ->
                    val proxy = available[index]
                    TextButton(
                        onClick = { onSelect(proxy) },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp),
                            horizontalAlignment = Alignment.Start
                        ) {
                            Text(
                                text = proxy.name,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = "${proxy.serverAddress}:${proxy.serverPort}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}
