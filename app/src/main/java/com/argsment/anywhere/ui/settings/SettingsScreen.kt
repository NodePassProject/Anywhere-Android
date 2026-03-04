package com.argsment.anywhere.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.AltRoute
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.viewmodel.VpnViewModel
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(viewModel: VpnViewModel) {
    var showRoutingRules by remember { mutableStateOf(false) }
    var showAcknowledgements by remember { mutableStateOf(false) }
    var showDoHAlert by remember { mutableStateOf(false) }

    var alwaysOn by remember { mutableStateOf(viewModel.alwaysOnEnabled) }
    var ipv6Enabled by remember { mutableStateOf(viewModel.ipv6Enabled) }
    var dohEnabled by remember { mutableStateOf(viewModel.dohEnabled) }
    var bypassCountryCode by remember { mutableStateOf(viewModel.bypassCountryCode) }

    if (showRoutingRules) {
        RuleSetListScreen(
            viewModel = viewModel,
            onBack = { showRoutingRules = false }
        )
        return
    }

    if (showAcknowledgements) {
        AcknowledgementsScreen(onBack = { showAcknowledgements = false })
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.settings)) })
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
            // VPN section
            SectionHeader(stringResource(R.string.vpn))
            SettingsSwitch(
                icon = Icons.Filled.Lock,
                iconTint = Color(0xFF2196F3),
                label = stringResource(R.string.always_on),
                checked = alwaysOn,
                onCheckedChange = {
                    alwaysOn = it
                    viewModel.alwaysOnEnabled = it
                }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Network section
            SectionHeader(stringResource(R.string.network))
            SettingsSwitch(
                icon = Icons.Filled.Language,
                iconTint = Color(0xFF009688),
                label = "IPv6",
                checked = ipv6Enabled,
                onCheckedChange = {
                    ipv6Enabled = it
                    viewModel.ipv6Enabled = it
                }
            )
            SettingsSwitch(
                icon = Icons.Filled.Shield,
                iconTint = Color(0xFF4CAF50),
                label = "DNS over HTTPS",
                checked = dohEnabled,
                onCheckedChange = { newValue ->
                    if (newValue) {
                        showDoHAlert = true
                    } else {
                        dohEnabled = false
                        viewModel.dohEnabled = false
                    }
                }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Routing section
            SectionHeader(stringResource(R.string.routing))
            SettingsNavRow(
                icon = Icons.Filled.AltRoute,
                iconTint = Color(0xFFFF9800),
                label = stringResource(R.string.routing_rules),
                onClick = { showRoutingRules = true }
            )
            CountryBypassPicker(
                icon = Icons.Filled.Public,
                iconTint = Color(0xFF9C27B0),
                selectedCode = bypassCountryCode,
                onSelect = {
                    bypassCountryCode = it
                    viewModel.bypassCountryCode = it
                }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // About section
            SectionHeader(stringResource(R.string.about))
            SettingsNavRow(
                icon = Icons.Filled.Info,
                iconTint = Color(0xFF9E9E9E),
                label = stringResource(R.string.acknowledgements),
                onClick = { showAcknowledgements = true }
            )
        }
    }

    // DoH Warning Alert
    if (showDoHAlert) {
        AlertDialog(
            onDismissRequest = { showDoHAlert = false },
            title = { Text("DNS over HTTPS") },
            text = { Text(stringResource(R.string.doh_routing_warning)) },
            confirmButton = {
                TextButton(onClick = {
                    showDoHAlert = false
                    dohEnabled = true
                    viewModel.dohEnabled = true
                }) {
                    Text(stringResource(R.string.enable_anyway))
                }
            },
            dismissButton = {
                TextButton(onClick = { showDoHAlert = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(vertical = 8.dp)
    )
}

@Composable
private fun SettingsIcon(
    icon: ImageVector,
    tint: Color,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .size(40.dp)
            .clip(CircleShape)
            .background(tint.copy(alpha = 0.15f)),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(24.dp)
        )
    }
}

@Composable
private fun SettingsSwitch(
    icon: ImageVector,
    iconTint: Color,
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SettingsIcon(icon = icon, tint = iconTint)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f)
        )
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun SettingsNavRow(
    icon: ImageVector,
    iconTint: Color,
    label: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SettingsIcon(icon = icon, tint = iconTint)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f)
        )
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

private val countryCodes = listOf("AE", "BY", "CN", "CU", "IR", "MM", "RU", "SA", "TM", "VN")

private fun flagForCountryCode(code: String): String {
    val firstChar = Character.toChars(0x1F1E6 - 'A'.code + code[0].uppercaseChar().code)
    val secondChar = Character.toChars(0x1F1E6 - 'A'.code + code[1].uppercaseChar().code)
    return String(firstChar) + String(secondChar)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CountryBypassPicker(
    icon: ImageVector,
    iconTint: Color,
    selectedCode: String,
    onSelect: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    val displayText = if (selectedCode.isEmpty()) {
        "Disable"
    } else {
        val locale = Locale("", selectedCode)
        "${flagForCountryCode(selectedCode)} ${locale.displayCountry}"
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SettingsIcon(icon = icon, tint = iconTint)
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it },
            modifier = Modifier.weight(1f)
        ) {
            OutlinedTextField(
                value = displayText,
                onValueChange = {},
                readOnly = true,
                label = { Text(stringResource(R.string.country_bypass)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor(MenuAnchorType.PrimaryNotEditable)
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.disable)) },
                    onClick = {
                        onSelect("")
                        expanded = false
                    }
                )
                countryCodes.forEach { code ->
                    val locale = Locale("", code)
                    DropdownMenuItem(
                        text = { Text("${flagForCountryCode(code)} ${locale.displayCountry}") },
                        onClick = {
                            onSelect(code)
                            expanded = false
                        }
                    )
                }
            }
        }
    }
}
