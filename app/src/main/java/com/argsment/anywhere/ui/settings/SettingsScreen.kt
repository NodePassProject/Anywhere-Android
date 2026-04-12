package com.argsment.anywhere.ui.settings

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
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
import androidx.compose.material.icons.automirrored.filled.CallMerge
import androidx.compose.material.icons.filled.AltRoute
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Tune
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
import com.argsment.anywhere.data.rules.CountryBypassCatalog
import com.argsment.anywhere.viewmodel.VpnViewModel
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(viewModel: VpnViewModel) {
    val context = LocalContext.current
    var showRoutingRules by remember { mutableStateOf(false) }
    var showAcknowledgements by remember { mutableStateOf(false) }
    var showTrustedCertificates by remember { mutableStateOf(false) }
    var showAdvancedSettings by remember { mutableStateOf(false) }
    var showInsecureAlert by remember { mutableStateOf(false) }

    var alwaysOn by remember { mutableStateOf(viewModel.alwaysOnEnabled) }
    var globalMode by remember { mutableStateOf(viewModel.proxyMode == "global") }
    var bypassCountryCode by remember { mutableStateOf(viewModel.bypassCountryCode) }
    var allowInsecure by remember { mutableStateOf(viewModel.allowInsecure) }

    // AD Blocking: check if the ADBlock rule set exists and its current assignment
    val adBlockRuleSet = remember { viewModel.ruleSetRepository.ruleSets.value.find { it.name == "ADBlock" } }
    var adBlockEnabled by remember {
        mutableStateOf(adBlockRuleSet?.assignedConfigurationId == "REJECT")
    }

    // Intercept the device back button when a sub-screen is showing.
    // Without this, the NavHost handles back press by popping the SettingsRoute,
    // sending the user to Home instead of back to the Settings list.
    val activeSubScreen = showRoutingRules || showAcknowledgements ||
            showTrustedCertificates || showAdvancedSettings
    BackHandler(enabled = activeSubScreen) {
        showRoutingRules = false
        showAcknowledgements = false
        showTrustedCertificates = false
        showAdvancedSettings = false
    }

    val currentRoute = when {
        showRoutingRules -> "routing"
        showAcknowledgements -> "acks"
        showTrustedCertificates -> "certs"
        showAdvancedSettings -> "advanced"
        else -> "root"
    }

    SubScreenHost(state = currentRoute, rootKey = "root") { route ->
        when (route) {
            "routing" -> RuleSetListScreen(
                viewModel = viewModel,
                onBack = { showRoutingRules = false }
            )
            "acks" -> AcknowledgementsScreen(onBack = { showAcknowledgements = false })
            "certs" -> TrustedCertificatesScreen(
                viewModel = viewModel,
                onBack = { showTrustedCertificates = false }
            )
            "advanced" -> AdvancedSettingsScreen(
                viewModel = viewModel,
                onBack = { showAdvancedSettings = false }
            )
            else -> SettingsRoot(
                alwaysOn = alwaysOn,
                onAlwaysOnChange = { alwaysOn = it; viewModel.alwaysOnEnabled = it },
                globalMode = globalMode,
                onGlobalModeChange = { globalMode = it; viewModel.proxyMode = if (it) "global" else "rule" },
                bypassCountryCode = bypassCountryCode,
                onBypassCountryChange = {
                    bypassCountryCode = it
                    viewModel.bypassCountryCode = it
                    viewModel.syncRoutingConfigurationToNE()
                },
                adBlockVisible = adBlockRuleSet != null,
                adBlockEnabled = adBlockEnabled,
                onAdBlockChange = { enabled ->
                    adBlockEnabled = enabled
                    if (adBlockRuleSet != null) {
                        viewModel.ruleSetRepository.updateAssignment(
                            adBlockRuleSet,
                            if (enabled) "REJECT" else null
                        )
                        viewModel.syncRoutingConfigurationToNE()
                    }
                },
                allowInsecure = allowInsecure,
                onAllowInsecureChange = { newValue ->
                    if (newValue) {
                        showInsecureAlert = true
                    } else {
                        allowInsecure = false
                        viewModel.allowInsecure = false
                    }
                },
                onOpenTelegram = {
                    context.startActivity(
                        Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/anywhere_official_group"))
                    )
                },
                onOpenRoutingRules = { showRoutingRules = true },
                onOpenTrustedCertificates = { showTrustedCertificates = true },
                onOpenAcknowledgements = { showAcknowledgements = true },
                onOpenAdvancedSettings = { showAdvancedSettings = true }
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsRoot(
    alwaysOn: Boolean,
    onAlwaysOnChange: (Boolean) -> Unit,
    globalMode: Boolean,
    onGlobalModeChange: (Boolean) -> Unit,
    bypassCountryCode: String,
    onBypassCountryChange: (String) -> Unit,
    adBlockVisible: Boolean,
    adBlockEnabled: Boolean,
    onAdBlockChange: (Boolean) -> Unit,
    allowInsecure: Boolean,
    onAllowInsecureChange: (Boolean) -> Unit,
    onOpenTelegram: () -> Unit,
    onOpenRoutingRules: () -> Unit,
    onOpenTrustedCertificates: () -> Unit,
    onOpenAcknowledgements: () -> Unit,
    onOpenAdvancedSettings: () -> Unit
) {
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
                onCheckedChange = onAlwaysOnChange
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Routing section
            SectionHeader(stringResource(R.string.routing))
            SettingsSwitch(
                icon = Icons.AutoMirrored.Filled.CallMerge,
                iconTint = Color(0xFFFF9800),
                label = stringResource(R.string.global_mode),
                checked = globalMode,
                onCheckedChange = onGlobalModeChange
            )
            if (!globalMode) {
                CountryBypassPicker(
                    icon = Icons.Filled.Public,
                    iconTint = Color(0xFFFF9800),
                    selectedCode = bypassCountryCode,
                    onSelect = onBypassCountryChange
                )
                if (adBlockVisible) {
                    SettingsSwitch(
                        icon = Icons.Filled.Shield,
                        iconTint = Color(0xFFE91E63),
                        label = stringResource(R.string.ad_blocking_title),
                        checked = adBlockEnabled,
                        onCheckedChange = onAdBlockChange
                    )
                }
                SettingsNavRow(
                    icon = Icons.Filled.AltRoute,
                    iconTint = Color(0xFF9C27B0),
                    label = stringResource(R.string.routing_rules),
                    onClick = onOpenRoutingRules
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Security section
            SectionHeader(stringResource(R.string.security))
            SettingsSwitch(
                icon = Icons.Filled.Warning,
                iconTint = Color(0xFFF44336),
                label = stringResource(R.string.allow_insecure),
                checked = allowInsecure,
                onCheckedChange = onAllowInsecureChange
            )
            SettingsNavRow(
                icon = Icons.Filled.VerifiedUser,
                iconTint = Color(0xFF4CAF50),
                label = stringResource(R.string.trusted_certificates),
                onClick = onOpenTrustedCertificates
            )

            Spacer(modifier = Modifier.height(16.dp))

            // About section
            SectionHeader(stringResource(R.string.about))
            SettingsNavRow(
                painter = painterResource(R.drawable.ic_telegram_symbol),
                iconTint = Color(0xFF039BE5),
                label = stringResource(R.string.join_telegram_group),
                onClick = onOpenTelegram
            )
            SettingsNavRow(
                icon = Icons.Filled.Info,
                iconTint = Color(0xFF9E9E9E),
                label = stringResource(R.string.acknowledgements),
                onClick = onOpenAcknowledgements
            )

            Spacer(modifier = Modifier.height(16.dp))

            SettingsNavRow(
                icon = Icons.Filled.Tune,
                iconTint = Color(0xFF546E7A),
                label = stringResource(R.string.advanced_settings),
                onClick = onOpenAdvancedSettings
            )
        }
    }
}

@Composable
internal fun SectionHeader(title: String) {
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
internal fun SettingsSwitch(
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
internal fun SettingsNavRow(
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
internal fun SettingsNavRow(
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
    val context = LocalContext.current
    val countryCodes = remember { CountryBypassCatalog.get(context).supportedCountryCodes }

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
