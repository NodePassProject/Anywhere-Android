package com.argsment.anywhere.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EncryptedDnsSettingsScreen(
    viewModel: VpnViewModel,
    onBack: () -> Unit
) {
    var enabled by remember { mutableStateOf(viewModel.encryptedDnsEnabled) }
    var dnsProtocol by remember { mutableStateOf(viewModel.encryptedDnsProtocol) }
    var serverText by remember { mutableStateOf(viewModel.encryptedDnsServer) }
    var showEnableAlert by remember { mutableStateOf(false) }

    DisposableEffect(Unit) {
        onDispose {
            val trimmed = serverText.trim()
            if (trimmed != viewModel.encryptedDnsServer) {
                viewModel.encryptedDnsServer = trimmed
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.encrypted_dns)) },
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
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.encrypted_dns),
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.weight(1f)
                )
                Switch(
                    checked = enabled,
                    onCheckedChange = { newValue ->
                        if (newValue) {
                            showEnableAlert = true
                        } else {
                            enabled = false
                            viewModel.encryptedDnsEnabled = false
                        }
                    }
                )
            }
            Text(
                text = stringResource(R.string.encrypted_dns_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (enabled) {
                Spacer(modifier = Modifier.height(4.dp))

                var protocolExpanded by remember { mutableStateOf(false) }
                val protocolDisplay = if (dnsProtocol == "doh")
                    stringResource(R.string.dns_over_https)
                else
                    stringResource(R.string.dns_over_tls)

                ExposedDropdownMenuBox(
                    expanded = protocolExpanded,
                    onExpandedChange = { protocolExpanded = it }
                ) {
                    OutlinedTextField(
                        value = protocolDisplay,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text(stringResource(R.string.dns_protocol)) },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = protocolExpanded) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                    )
                    ExposedDropdownMenu(
                        expanded = protocolExpanded,
                        onDismissRequest = { protocolExpanded = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.dns_over_https)) },
                            onClick = {
                                dnsProtocol = "doh"
                                viewModel.encryptedDnsProtocol = "doh"
                                protocolExpanded = false
                            }
                        )
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.dns_over_tls)) },
                            onClick = {
                                dnsProtocol = "dot"
                                viewModel.encryptedDnsProtocol = "dot"
                                protocolExpanded = false
                            }
                        )
                    }
                }

                OutlinedTextField(
                    value = serverText,
                    onValueChange = { serverText = it },
                    label = { Text(stringResource(R.string.dns_server)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
                )
                Text(
                    text = stringResource(R.string.dns_server_footer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }

    if (showEnableAlert) {
        AlertDialog(
            onDismissRequest = { showEnableAlert = false },
            title = { Text(stringResource(R.string.encrypted_dns)) },
            text = { Text(stringResource(R.string.encrypted_dns_warning)) },
            confirmButton = {
                TextButton(onClick = {
                    showEnableAlert = false
                    enabled = true
                    viewModel.encryptedDnsEnabled = true
                }) {
                    Text(stringResource(R.string.enable_anyway))
                }
            },
            dismissButton = {
                TextButton(onClick = { showEnableAlert = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}
