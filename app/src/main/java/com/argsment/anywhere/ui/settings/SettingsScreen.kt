package com.argsment.anywhere.ui.settings

import android.content.Intent
import android.net.Uri
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
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
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
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.viewmodel.VpnViewModel
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(viewModel: VpnViewModel) {
    val context = LocalContext.current
    var showRoutingRules by remember { mutableStateOf(false) }
    var showAcknowledgements by remember { mutableStateOf(false) }
    var showIpv6Settings by remember { mutableStateOf(false) }
    var showEncryptedDns by remember { mutableStateOf(false) }
    var showTrustedCertificates by remember { mutableStateOf(false) }
    var showInsecureAlert by remember { mutableStateOf(false) }

    var alwaysOn by remember { mutableStateOf(viewModel.alwaysOnEnabled) }
    var bypassCountryCode by remember { mutableStateOf(viewModel.bypassCountryCode) }
    var allowInsecure by remember { mutableStateOf(viewModel.allowInsecure) }

    // AD Blocking: check if the ADBlock rule set exists and its current assignment
    val adBlockRuleSet = remember { viewModel.ruleSetRepository.ruleSets.value.find { it.name == "ADBlock" } }
    var adBlockEnabled by remember {
        mutableStateOf(adBlockRuleSet?.assignedConfigurationId == "REJECT")
    }

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

    if (showIpv6Settings) {
        Ipv6SettingsScreen(
            viewModel = viewModel,
            onBack = { showIpv6Settings = false }
        )
        return
    }

    if (showEncryptedDns) {
        EncryptedDnsSettingsScreen(
            viewModel = viewModel,
            onBack = { showEncryptedDns = false }
        )
        return
    }

    if (showTrustedCertificates) {
        TrustedCertificatesScreen(
            viewModel = viewModel,
            onBack = { showTrustedCertificates = false }
        )
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
            SettingsNavRow(
                icon = Icons.Filled.Language,
                iconTint = Color(0xFF2196F3),
                label = stringResource(R.string.ipv6),
                onClick = { showIpv6Settings = true }
            )
            SettingsNavRow(
                icon = Icons.Filled.Shield,
                iconTint = Color(0xFF009688),
                label = stringResource(R.string.encrypted_dns),
                onClick = { showEncryptedDns = true }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Routing section
            SectionHeader(stringResource(R.string.routing))
            CountryBypassPicker(
                icon = Icons.Filled.Public,
                iconTint = Color(0xFFFF9800),
                selectedCode = bypassCountryCode,
                onSelect = {
                    bypassCountryCode = it
                    viewModel.bypassCountryCode = it
                }
            )
            if (adBlockRuleSet != null) {
                SettingsSwitch(
                    icon = Icons.Filled.Shield,
                    iconTint = Color(0xFFE91E63),
                    label = stringResource(R.string.ad_blocking_title),
                    checked = adBlockEnabled,
                    onCheckedChange = { enabled ->
                        adBlockEnabled = enabled
                        viewModel.ruleSetRepository.updateAssignment(
                            adBlockRuleSet,
                            if (enabled) "REJECT" else null
                        )
                        viewModel.syncRoutingConfigurationToNE()
                    }
                )
            }
            SettingsNavRow(
                icon = Icons.Filled.AltRoute,
                iconTint = Color(0xFF9C27B0),
                label = stringResource(R.string.routing_rules),
                onClick = { showRoutingRules = true }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Security section
            SectionHeader(stringResource(R.string.security))
            SettingsSwitch(
                icon = Icons.Filled.Warning,
                iconTint = Color(0xFFF44336),
                label = stringResource(R.string.allow_insecure),
                checked = allowInsecure,
                onCheckedChange = { newValue ->
                    if (newValue) {
                        showInsecureAlert = true
                    } else {
                        allowInsecure = false
                        viewModel.allowInsecure = false
                    }
                }
            )
            SettingsNavRow(
                icon = Icons.Filled.VerifiedUser,
                iconTint = Color(0xFF4CAF50),
                label = stringResource(R.string.trusted_certificates),
                onClick = { showTrustedCertificates = true }
            )

            Spacer(modifier = Modifier.height(16.dp))

            // About section
            SectionHeader(stringResource(R.string.about))
            SettingsNavRow(
                painter = painterResource(R.drawable.ic_brand_telegram),
                iconTint = Color(0xFF039BE5),
                label = stringResource(R.string.join_telegram_group),
                onClick = {
                    context.startActivity(
                        Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/anywhere_official_group"))
                    )
                }
            )
            SettingsNavRow(
                icon = Icons.Filled.Info,
                iconTint = Color(0xFF9E9E9E),
                label = stringResource(R.string.acknowledgements),
                onClick = { showAcknowledgements = true }
            )
        }
    }

    // Allow Insecure Warning Alert
    if (showInsecureAlert) {
        AlertDialog(
            onDismissRequest = { showInsecureAlert = false },
            title = { Text(stringResource(R.string.allow_insecure)) },
            text = { Text(stringResource(R.string.allow_insecure_warning)) },
            confirmButton = {
                TextButton(onClick = {
                    showInsecureAlert = false
                    allowInsecure = true
                    viewModel.allowInsecure = true
                }) {
                    Text(stringResource(R.string.allow_anyway))
                }
            },
            dismissButton = {
                TextButton(onClick = { showInsecureAlert = false }) {
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
    SettingsIconContainer(tint = tint, modifier = modifier) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(24.dp)
        )
    }
}

@Composable
private fun SettingsIcon(
    painter: Painter,
    tint: Color,
    modifier: Modifier = Modifier
) {
    SettingsIconContainer(tint = tint, modifier = modifier) {
        Icon(
            painter = painter,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(24.dp)
        )
    }
}

@Composable
private fun SettingsIconContainer(
    tint: Color,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    Box(
        modifier = modifier
            .size(40.dp)
            .clip(CircleShape)
            .background(tint.copy(alpha = 0.15f)),
        contentAlignment = Alignment.Center
    ) {
        content()
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

@Composable
private fun SettingsNavRow(
    painter: Painter,
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
        SettingsIcon(painter = painter, tint = iconTint)
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
        stringResource(R.string.disable)
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
