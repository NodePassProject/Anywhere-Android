package com.argsment.anywhere.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Lan
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.data.model.DomainRule
import com.argsment.anywhere.data.model.DomainRuleType
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.Subscription
import com.argsment.anywhere.data.repository.RuleSetRepository
import com.argsment.anywhere.viewmodel.VpnViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Editor for a single user-created rule set.
 *
 * Supports: viewing rules, adding a rule manually, bulk-importing rules (paste or
 * URL download), deleting individual rules, renaming the rule set, and picking an
 * assignment (Default / DIRECT / REJECT / proxy).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomRuleSetDetailScreen(
    viewModel: VpnViewModel,
    customRuleSetId: String,
    onBack: () -> Unit
) {
    val customRuleSets by viewModel.ruleSetRepository.customRuleSets.collectAsState()
    val ruleSets by viewModel.ruleSetRepository.ruleSets.collectAsState()
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()

    val customRuleSet = remember(customRuleSets, customRuleSetId) {
        customRuleSets.firstOrNull { it.id == customRuleSetId }
    }
    val ruleSet = remember(ruleSets, customRuleSetId) {
        ruleSets.firstOrNull { it.id == customRuleSetId }
    }

    val standaloneConfigs = remember(configurations) {
        configurations.filter { it.subscriptionId == null }
    }
    val subscribedGroups = remember(configurations, subscriptions) {
        subscriptions.mapNotNull { sub ->
            val cfgs = configurations.filter { it.subscriptionId == sub.id }
            if (cfgs.isEmpty()) null else sub to cfgs
        }
    }

    var showAddRule by remember { mutableStateOf(false) }
    var showImport by remember { mutableStateOf(false) }
    var showRename by remember { mutableStateOf(false) }
    var renameText by remember { mutableStateOf(customRuleSet?.name ?: "") }
    var menuOpen by remember { mutableStateOf(false) }

    // If the rule set got deleted from under us, close the screen.
    LaunchedEffect(customRuleSet) {
        if (customRuleSet == null) onBack()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(customRuleSet?.name ?: stringResource(R.string.rule_set)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                actions = {
                    Box {
                        IconButton(onClick = { menuOpen = true }) {
                            Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.more))
                        }
                        DropdownMenu(
                            expanded = menuOpen,
                            onDismissRequest = { menuOpen = false }
                        ) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.add_rule)) },
                                leadingIcon = { Icon(Icons.Filled.Add, contentDescription = null) },
                                onClick = { menuOpen = false; showAddRule = true }
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.import_rules)) },
                                leadingIcon = { Icon(Icons.Filled.FileDownload, contentDescription = null) },
                                onClick = { menuOpen = false; showImport = true }
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.rename)) },
                                leadingIcon = { Icon(Icons.Filled.Edit, contentDescription = null) },
                                onClick = {
                                    menuOpen = false
                                    renameText = customRuleSet?.name ?: ""
                                    showRename = true
                                }
                            )
                        }
                    }
                }
            )
        }
    ) { innerPadding ->
        val rules = customRuleSet?.rules.orEmpty()
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
        ) {
            if (ruleSet != null) {
                AssignmentPicker(
                    assignedId = ruleSet.assignedConfigurationId,
                    standaloneConfigs = standaloneConfigs,
                    subscribedGroups = subscribedGroups,
                    onAssign = { newValue ->
                        viewModel.ruleSetRepository.updateAssignment(ruleSet, newValue)
                        viewModel.syncRoutingConfigurationToNE()
                    }
                )
                Spacer(modifier = Modifier.height(12.dp))
            }

            Text(
                text = stringResource(R.string.rules),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(4.dp))

            LazyColumn(modifier = Modifier.weight(1f)) {
                items(rules.size, key = { it }) { index ->
                    RuleRow(
                        rule = rules[index],
                        onDelete = {
                            viewModel.ruleSetRepository.removeRules(customRuleSetId, listOf(index))
                            viewModel.syncRoutingConfigurationToNE()
                        }
                    )
                }
            }
        }
    }

    if (showAddRule) {
        AddRuleSheet(
            onDismiss = { showAddRule = false },
            onAdd = { type, value ->
                viewModel.ruleSetRepository.addRule(customRuleSetId, DomainRule(type, value))
                viewModel.syncRoutingConfigurationToNE()
                showAddRule = false
            }
        )
    }

    if (showImport) {
        ImportRulesSheet(
            onDismiss = { showImport = false },
            onImport = { parsed ->
                viewModel.ruleSetRepository.addRules(customRuleSetId, parsed)
                viewModel.syncRoutingConfigurationToNE()
                showImport = false
            }
        )
    }

    if (showRename) {
        RenameDialog(
            initialName = renameText,
            onDismiss = { showRename = false },
            onRename = { newName ->
                viewModel.ruleSetRepository.updateCustomRuleSet(customRuleSetId, name = newName)
                showRename = false
            }
        )
    }
}

@Composable
private fun RuleRow(rule: DomainRule, onDelete: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Per-type leading icon mirrors iOS CustomRuleSetDetailView.iconName.
        Icon(
            imageVector = ruleTypeIcon(rule.type),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier
                .size(24.dp)
                .padding(end = 8.dp)
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = rule.value,
                style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = ruleTypeLabel(rule.type),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        IconButton(onClick = onDelete) {
            Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.delete))
        }
    }
}

private fun ruleTypeIcon(type: DomainRuleType) = when (type) {
    DomainRuleType.DOMAIN_SUFFIX -> Icons.Filled.Public
    DomainRuleType.DOMAIN_KEYWORD -> Icons.Filled.Search
    DomainRuleType.IP_CIDR, DomainRuleType.IP_CIDR6 -> Icons.Filled.Lan
}

@Composable
private fun ruleTypeLabel(type: DomainRuleType): String = when (type) {
    DomainRuleType.DOMAIN_SUFFIX -> stringResource(R.string.domain_suffix)
    DomainRuleType.DOMAIN_KEYWORD -> stringResource(R.string.domain_keyword)
    DomainRuleType.IP_CIDR -> stringResource(R.string.ipv4_cidr)
    DomainRuleType.IP_CIDR6 -> stringResource(R.string.ipv6_cidr)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AssignmentPicker(
    assignedId: String?,
    standaloneConfigs: List<ProxyConfiguration>,
    subscribedGroups: List<Pair<Subscription, List<ProxyConfiguration>>>,
    onAssign: (String?) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val allConfigs = standaloneConfigs + subscribedGroups.flatMap { it.second }
    val displayText = when (assignedId) {
        null -> stringResource(R.string.default_value)
        "DIRECT" -> stringResource(R.string.direct)
        "REJECT" -> stringResource(R.string.reject)
        else -> allConfigs.firstOrNull { it.id.toString() == assignedId }?.name
            ?: stringResource(R.string.default_value)
    }

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it }
    ) {
        OutlinedTextField(
            value = displayText,
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.route_to)) },
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
                text = { Text(stringResource(R.string.default_value)) },
                onClick = { onAssign(null); expanded = false }
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.direct)) },
                onClick = { onAssign("DIRECT"); expanded = false }
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.reject)) },
                onClick = { onAssign("REJECT"); expanded = false }
            )
            standaloneConfigs.forEach { config ->
                DropdownMenuItem(
                    text = { Text(config.name) },
                    onClick = { onAssign(config.id.toString()); expanded = false }
                )
            }
            subscribedGroups.forEach { (subscription, configs) ->
                DropdownMenuItem(
                    text = {
                        Text(
                            text = subscription.name,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    },
                    onClick = {},
                    enabled = false
                )
                configs.forEach { config ->
                    DropdownMenuItem(
                        text = { Text("  ${config.name}") },
                        onClick = { onAssign(config.id.toString()); expanded = false }
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddRuleSheet(
    onDismiss: () -> Unit,
    onAdd: (DomainRuleType, String) -> Unit
) {
    var type by remember { mutableStateOf(DomainRuleType.DOMAIN_SUFFIX) }
    var value by remember { mutableStateOf("") }
    var typeMenuOpen by remember { mutableStateOf(false) }

    val placeholder = when (type) {
        DomainRuleType.DOMAIN_SUFFIX -> stringResource(R.string.example_domain)
        DomainRuleType.DOMAIN_KEYWORD -> stringResource(R.string.example_keyword)
        DomainRuleType.IP_CIDR -> stringResource(R.string.example_ipv4)
        DomainRuleType.IP_CIDR6 -> stringResource(R.string.example_ipv6)
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
                Text(stringResource(R.string.add_rule), style = MaterialTheme.typography.titleMedium)
                TextButton(
                    onClick = { onAdd(type, value.trim()) },
                    enabled = value.trim().isNotEmpty()
                ) { Text(stringResource(R.string.add)) }
            }
            Spacer(modifier = Modifier.height(12.dp))

            ExposedDropdownMenuBox(
                expanded = typeMenuOpen,
                onExpandedChange = { typeMenuOpen = it }
            ) {
                OutlinedTextField(
                    value = ruleTypeLabel(type),
                    onValueChange = {},
                    readOnly = true,
                    label = { Text(stringResource(R.string.type_label)) },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = typeMenuOpen) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                )
                ExposedDropdownMenu(
                    expanded = typeMenuOpen,
                    onDismissRequest = { typeMenuOpen = false }
                ) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.domain_suffix)) },
                        onClick = { type = DomainRuleType.DOMAIN_SUFFIX; typeMenuOpen = false }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.domain_keyword)) },
                        onClick = { type = DomainRuleType.DOMAIN_KEYWORD; typeMenuOpen = false }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.ipv4_cidr)) },
                        onClick = { type = DomainRuleType.IP_CIDR; typeMenuOpen = false }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.ipv6_cidr)) },
                        onClick = { type = DomainRuleType.IP_CIDR6; typeMenuOpen = false }
                    )
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = value,
                onValueChange = { value = it },
                label = { Text(stringResource(R.string.value_label)) },
                placeholder = { Text(placeholder) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ImportRulesSheet(
    onDismiss: () -> Unit,
    onImport: (List<DomainRule>) -> Unit
) {
    var text by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var downloading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    val parsed = remember(text) { RuleParser.parse(text) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ) {
        Column(
            modifier = Modifier
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
                Text(stringResource(R.string.import_rules), style = MaterialTheme.typography.titleMedium)
                TextButton(
                    onClick = { onImport(parsed) },
                    enabled = parsed.isNotEmpty()
                ) { Text(stringResource(R.string.import_action)) }
            }
            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text(stringResource(R.string.rules)) },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 160.dp, max = 280.dp)
            )

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = stringResource(R.string.download_from_internet),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(4.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text(stringResource(R.string.rule_list_url)) },
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Button(
                    onClick = {
                        val trimmed = url.trim()
                        if (trimmed.isEmpty()) return@Button
                        error = null
                        downloading = true
                        scope.launch {
                            val result = runCatching {
                                withContext(Dispatchers.IO) {
                                    val conn = URL(trimmed).openConnection() as HttpURLConnection
                                    conn.connectTimeout = 15000
                                    conn.readTimeout = 30000
                                    try {
                                        val code = conn.responseCode
                                        if (code !in 200..299) {
                                            throw IllegalStateException("HTTP $code")
                                        }
                                        conn.inputStream.bufferedReader().use { it.readText() }
                                    } finally {
                                        conn.disconnect()
                                    }
                                }
                            }
                            downloading = false
                            result
                                .onSuccess { text = it }
                                .onFailure { error = it.message ?: "Download failed" }
                        }
                    },
                    enabled = url.trim().isNotEmpty() && !downloading
                ) {
                    if (downloading) {
                        CircularProgressIndicator(modifier = Modifier.height(16.dp).width(16.dp))
                    } else {
                        Icon(Icons.Filled.Download, contentDescription = stringResource(R.string.download))
                    }
                }
            }

            error?.let { msg ->
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = msg,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }

            if (parsed.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.parsed_rules, parsed.size),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun RenameDialog(
    initialName: String,
    onDismiss: () -> Unit,
    onRename: (String) -> Unit
) {
    var name by remember(initialName) { mutableStateOf(initialName) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.rename_rule_set)) },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.name_label)) },
                singleLine = true
            )
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val trimmed = name.trim()
                    if (trimmed.isNotEmpty()) onRename(trimmed)
                },
                enabled = name.trim().isNotEmpty()
            ) { Text(stringResource(R.string.rename)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

// Line format: "type, value" where type is 0 (IPv4 CIDR), 1 (IPv6 CIDR),
// 2 (Domain Suffix), or 3 (Domain Keyword). Comment lines (#, //) and blanks
// are ignored. Bare IPs are normalised to /32 (v4) and /128 (v6).
internal object RuleParser {

    fun parse(text: String): List<DomainRule> = text.lineSequence()
        .mapNotNull { parseLine(it) }
        .toList()

    private fun parseLine(line: String): DomainRule? {
        val trimmed = line.trim()
        if (trimmed.isEmpty()) return null
        if (trimmed.startsWith("#") || trimmed.startsWith("//")) return null

        val commaIndex = trimmed.indexOf(',')
        if (commaIndex < 0) return null
        val prefix = trimmed.substring(0, commaIndex).trim()
        val value = trimmed.substring(commaIndex + 1).trim()
        if (value.isEmpty()) return null

        val typeInt = prefix.toIntOrNull() ?: return null
        val type = DomainRuleType.fromRawValue(typeInt) ?: return null
        return DomainRule(type, normalize(value, type))
    }

    private fun normalize(value: String, type: DomainRuleType): String = when (type) {
        DomainRuleType.IP_CIDR -> if ("/" in value) value else "$value/32"
        DomainRuleType.IP_CIDR6 -> if ("/" in value) value else "$value/128"
        DomainRuleType.DOMAIN_SUFFIX,
        DomainRuleType.DOMAIN_KEYWORD -> value
    }
}
