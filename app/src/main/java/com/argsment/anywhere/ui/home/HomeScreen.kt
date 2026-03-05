package com.argsment.anywhere.ui.home

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.isSystemInDarkTheme
import com.argsment.anywhere.R
import com.argsment.anywhere.ui.components.PowerButton
import com.argsment.anywhere.ui.components.TrafficStatsRow
import com.argsment.anywhere.ui.theme.GradientConnectedEndDark
import com.argsment.anywhere.ui.theme.GradientConnectedEndLight
import com.argsment.anywhere.ui.theme.GradientConnectedStartDark
import com.argsment.anywhere.ui.theme.GradientConnectedStartLight
import com.argsment.anywhere.ui.theme.GradientDisconnectedEndDark
import com.argsment.anywhere.ui.theme.GradientDisconnectedEndLight
import com.argsment.anywhere.ui.theme.GradientDisconnectedStartDark
import com.argsment.anywhere.ui.theme.GradientDisconnectedStartLight
import com.argsment.anywhere.ui.proxy.AddProxyScreen
import com.argsment.anywhere.ui.proxy.ProxyEditorScreen
import com.argsment.anywhere.viewmodel.VpnStatus
import com.argsment.anywhere.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(viewModel: VpnViewModel, contentPadding: PaddingValues = PaddingValues()) {
    val vpnStatus by viewModel.vpnStatus.collectAsState()
    val bytesIn by viewModel.bytesIn.collectAsState()
    val bytesOut by viewModel.bytesOut.collectAsState()
    val selectedConfigId by viewModel.selectedConfigId.collectAsState()
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val startError by viewModel.startError.collectAsState()

    val isConnected = vpnStatus == VpnStatus.CONNECTED
    val isTransitioning = vpnStatus == VpnStatus.CONNECTING ||
            vpnStatus == VpnStatus.DISCONNECTING ||
            vpnStatus == VpnStatus.REASSERTING

    val selectedConfig = remember(selectedConfigId, configurations) {
        selectedConfigId?.let { id -> configurations.find { it.id == id } }
    }

    var showingAddSheet by remember { mutableStateOf(false) }
    var showingManualAddSheet by remember { mutableStateOf(false) }
    var showingConfigPicker by remember { mutableStateOf(false) }

    // Background gradient colors
    val isDark = isSystemInDarkTheme()
    val gradientStart by animateColorAsState(
        targetValue = when {
            isConnected && isDark -> GradientConnectedStartDark
            isConnected -> GradientConnectedStartLight
            isDark -> GradientDisconnectedStartDark
            else -> GradientDisconnectedStartLight
        },
        animationSpec = tween(600),
        label = "gradientStart"
    )
    val gradientEnd by animateColorAsState(
        targetValue = when {
            isConnected && isDark -> GradientConnectedEndDark
            isConnected -> GradientConnectedEndLight
            isDark -> GradientDisconnectedEndDark
            else -> GradientDisconnectedEndLight
        },
        animationSpec = tween(600),
        label = "gradientEnd"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.linearGradient(
                    colors = listOf(gradientStart, gradientEnd)
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(contentPadding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Spacer(modifier = Modifier.weight(1f))

            // Power button
            PowerButton(
                isConnected = isConnected,
                isTransitioning = isTransitioning,
                enabled = !viewModel.isButtonDisabled,
                onClick = { viewModel.toggleVPN() }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Status text
            val statusTextRes = when (vpnStatus) {
                VpnStatus.DISCONNECTED -> R.string.disconnected
                VpnStatus.CONNECTING -> R.string.connecting
                VpnStatus.CONNECTED -> R.string.connected
                VpnStatus.DISCONNECTING -> R.string.disconnecting
                VpnStatus.REASSERTING -> R.string.reconnecting
            }
            Text(
                text = stringResource(statusTextRes),
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Medium),
                color = if (isConnected) Color.White else MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(if (isConnected) 20.dp else 40.dp))

            // Traffic stats (when connected)
            AnimatedVisibility(
                visible = isConnected,
                enter = slideInVertically(initialOffsetY = { it }) + fadeIn(),
                exit = slideOutVertically(targetOffsetY = { it }) + fadeOut()
            ) {
                Card(
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = Color.White.copy(alpha = 0.15f)
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 20.dp)
                ) {
                    TrafficStatsRow(
                        bytesIn = bytesIn,
                        bytesOut = bytesOut,
                        contentColor = Color.White,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }

            // Configuration card
            if (selectedConfig != null) {
                Card(
                    onClick = { showingConfigPicker = true },
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = if (isConnected) Color.White.copy(alpha = 0.15f) else MaterialTheme.colorScheme.surfaceContainerHigh
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.ic_network_filled),
                            contentDescription = null,
                            tint = if (isConnected) Color.White.copy(alpha = 0.7f) else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = selectedConfig.name,
                            style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium),
                            color = if (isConnected) Color.White else MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.weight(1f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Icon(
                            imageVector = Icons.Default.KeyboardArrowDown,
                            contentDescription = null,
                            tint = if (isConnected) Color.White.copy(alpha = 0.4f) else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
                        )
                    }
                }
            } else {
                Card(
                    onClick = { showingAddSheet = true },
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = stringResource(R.string.add_a_configuration),
                            style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium),
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.weight(1f))
        }
    }

    // Config picker bottom sheet
    if (showingConfigPicker) {
        ModalBottomSheet(
            onDismissRequest = { showingConfigPicker = false },
            sheetState = rememberModalBottomSheetState()
        ) {
            Column(modifier = Modifier.padding(bottom = 24.dp)) {
                Text(
                    text = stringResource(R.string.proxies),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp)
                )
                configurations.forEach { config ->
                    val isSelected = config.id == selectedConfigId
                    Surface(
                        onClick = {
                            viewModel.setSelectedConfiguration(config)
                            showingConfigPicker = false
                        },
                        color = if (isSelected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 24.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = config.name,
                                style = MaterialTheme.typography.bodyLarge,
                                modifier = Modifier.weight(1f)
                            )
                            if (isSelected) {
                                Text(
                                    text = "\u2713",
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
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

    // Error dialog
    if (startError != null) {
        AlertDialog(
            onDismissRequest = { viewModel.clearStartError() },
            title = { Text(stringResource(R.string.vpn_error)) },
            text = { Text(startError ?: "") },
            confirmButton = {
                TextButton(onClick = { viewModel.clearStartError() }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}
