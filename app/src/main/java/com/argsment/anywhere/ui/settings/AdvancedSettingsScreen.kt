package com.argsment.anywhere.ui.settings

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ReceiptLong
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.viewmodel.VpnViewModel

/**
 * Advanced Settings screen, matching iOS `AdvancedSettingsView`:
 *   Network → IPv6, Encrypted DNS
 *   Diagnostics → Logs
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdvancedSettingsScreen(
    viewModel: VpnViewModel,
    onBack: () -> Unit
) {
    var showIpv6Settings by remember { mutableStateOf(false) }
    var showEncryptedDns by remember { mutableStateOf(false) }
    var showLogs by remember { mutableStateOf(false) }

    val activeSubScreen = showIpv6Settings || showEncryptedDns || showLogs
    BackHandler(enabled = activeSubScreen) {
        showIpv6Settings = false
        showEncryptedDns = false
        showLogs = false
    }

    val currentRoute = when {
        showIpv6Settings -> "ipv6"
        showEncryptedDns -> "dns"
        showLogs -> "logs"
        else -> "root"
    }

    SubScreenHost(state = currentRoute, rootKey = "root") { route ->
        when (route) {
            "ipv6" -> Ipv6SettingsScreen(viewModel = viewModel, onBack = { showIpv6Settings = false })
            "dns" -> EncryptedDnsSettingsScreen(viewModel = viewModel, onBack = { showEncryptedDns = false })
            "logs" -> LogListScreen(onBack = { showLogs = false })
            else -> AdvancedSettingsRoot(
                viewModel = viewModel,
                onBack = onBack,
                onOpenIpv6 = { showIpv6Settings = true },
                onOpenEncryptedDns = { showEncryptedDns = true },
                onOpenLogs = { showLogs = true }
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AdvancedSettingsRoot(
    viewModel: VpnViewModel,
    onBack: () -> Unit,
    onOpenIpv6: () -> Unit,
    onOpenEncryptedDns: () -> Unit,
    onOpenLogs: () -> Unit
) {
    var experimentalEnabled by remember { mutableStateOf(viewModel.experimentalEnabled) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.advanced_settings)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            SectionHeader(stringResource(R.string.network))
            SettingsNavRow(
                icon = Icons.Filled.Language,
                iconTint = Color(0xFF2196F3),
                label = stringResource(R.string.ipv6),
                onClick = onOpenIpv6
            )
            SettingsNavRow(
                icon = Icons.Filled.Shield,
                iconTint = Color(0xFF009688),
                label = stringResource(R.string.encrypted_dns),
                onClick = onOpenEncryptedDns
            )

            Spacer(modifier = Modifier.height(16.dp))

            SectionHeader(stringResource(R.string.diagnostics))
            SettingsNavRow(
                icon = Icons.AutoMirrored.Filled.ReceiptLong,
                iconTint = Color(0xFF607D8B),
                label = stringResource(R.string.logs),
                onClick = onOpenLogs
            )

            Spacer(modifier = Modifier.height(16.dp))

            SectionHeader(stringResource(R.string.experimental))
            SettingsSwitch(
                icon = Icons.Filled.Science,
                iconTint = Color(0xFFAB47BC),
                label = stringResource(R.string.experimental_features),
                checked = experimentalEnabled,
                onCheckedChange = {
                    experimentalEnabled = it
                    viewModel.experimentalEnabled = it
                }
            )
            Text(
                text = stringResource(R.string.experimental_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 56.dp, top = 2.dp, bottom = 8.dp)
            )
        }
    }
}
