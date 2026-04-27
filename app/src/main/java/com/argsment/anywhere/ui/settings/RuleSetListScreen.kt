package com.argsment.anywhere.ui.settings

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.automirrored.filled.Rule
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import com.argsment.anywhere.data.model.Subscription
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.repository.RuleSetRepository
import com.argsment.anywhere.ui.components.AppIconView
import com.argsment.anywhere.viewmodel.VpnViewModel

/**
 * Shows built-in service rule sets (Direct + ADBlock are excluded: Direct is
 * always-direct, ADBlock is toggled from the root Settings screen). Below the
 * built-ins, lists user-created custom rule sets and navigates into
 * [CustomRuleSetDetailScreen] on tap. Adding new custom rule sets is gated
 * behind [VpnViewModel.experimentalEnabled].
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RuleSetListScreen(
    viewModel: VpnViewModel,
    onBack: () -> Unit
) {
    var openCustomId by remember { mutableStateOf<String?>(null) }
    BackHandler(enabled = openCustomId != null) { openCustomId = null }

    val route = openCustomId
    SubScreenHost(state = route, rootKey = null) { current ->
        if (current == null) {
            RuleSetListRoot(
                viewModel = viewModel,
                onBack = onBack,
                onOpenCustom = { id -> openCustomId = id }
            )
        } else {
            CustomRuleSetDetailScreen(
                viewModel = viewModel,
                customRuleSetId = current,
                onBack = { openCustomId = null }
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RuleSetListRoot(
    viewModel: VpnViewModel,
    onBack: () -> Unit,
    onOpenCustom: (String) -> Unit
) {
    val ruleSets by viewModel.ruleSetRepository.ruleSets.collectAsState()
    val customRuleSets by viewModel.ruleSetRepository.customRuleSets.collectAsState()
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()

    val builtInServiceRuleSets = remember(ruleSets) {
        ruleSets.filter { !it.isCustom && it.name != "ADBlock" && it.id != "Direct" }
    }

    val standaloneConfigs = remember(configurations) {
        configurations.filter { it.subscriptionId == null }
    }
    val subscribedGroups = remember(configurations, subscriptions) {
        subscriptions.mapNotNull { subscription ->
            val configs = configurations.filter { it.subscriptionId == subscription.id }
            if (configs.isEmpty()) null else subscription to configs
        }
    }

    val experimentalEnabled = remember { viewModel.experimentalEnabled }
    var menuOpen by remember { mutableStateOf(false) }
    var showNewDialog by remember { mutableStateOf(false) }
    var pendingDeleteId by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.routing_rules)) },
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
                            if (experimentalEnabled) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.new_rule_set)) },
                                    leadingIcon = { Icon(Icons.Filled.Add, contentDescription = null) },
                                    onClick = {
                                        menuOpen = false
                                        showNewDialog = true
                                    }
                                )
                            }
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.reset)) },
                                leadingIcon = { Icon(Icons.Filled.Refresh, contentDescription = null) },
                                onClick = {
                                    menuOpen = false
                                    viewModel.ruleSetRepository.resetAssignments()
                                    viewModel.syncRoutingConfigurationToNE()
                                }
                            )
                        }
                    }
                }
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
        ) {
            items(builtInServiceRuleSets, key = { it.id }) { ruleSet ->
                RuleSetRow(
                    ruleSet = ruleSet,
                    standaloneConfigs = standaloneConfigs,
                    subscribedGroups = subscribedGroups,
                    onAssign = { configId ->
                        viewModel.ruleSetRepository.updateAssignment(ruleSet, configId)
                        viewModel.syncRoutingConfigurationToNE()
                    }
                )
            }

            if (customRuleSets.isNotEmpty()) {
                item {
                    Spacer(modifier = Modifier.height(12.dp))
                    HorizontalDivider()
                    Text(
                        text = stringResource(R.string.custom),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 8.dp)
                    )
                }
                items(customRuleSets, key = { it.id }) { custom ->
                    val assignment = ruleSets.firstOrNull { it.id == custom.id }?.assignedConfigurationId
                    CustomRuleSetRow(
                        name = custom.name,
                        ruleCount = custom.rules.size,
                        assignmentLabel = assignmentLabel(assignment, standaloneConfigs, subscribedGroups),
                        onOpen = { onOpenCustom(custom.id) },
                        onDelete = { pendingDeleteId = custom.id }
                    )
                }
            }
        }
    }

    if (showNewDialog) {
        NewRuleSetDialog(
            onDismiss = { showNewDialog = false },
            onCreate = { name ->
                val created = viewModel.ruleSetRepository.addCustomRuleSet(name)
                showNewDialog = false
                onOpenCustom(created.id)
            }
        )
    }

    pendingDeleteId?.let { id ->
        val name = customRuleSets.firstOrNull { it.id == id }?.name.orEmpty()
        AlertDialog(
            onDismissRequest = { pendingDeleteId = null },
            title = { Text(stringResource(R.string.delete)) },
            text = { Text(name) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.ruleSetRepository.removeCustomRuleSet(id)
                    viewModel.syncRoutingConfigurationToNE()
                    pendingDeleteId = null
                }) { Text(stringResource(R.string.delete)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDeleteId = null }) { Text(stringResource(R.string.cancel)) }
            }
        )
    }
}

@Composable
private fun assignmentLabel(
    assignedId: String?,
    standaloneConfigs: List<ProxyConfiguration>,
    subscribedGroups: List<Pair<Subscription, List<ProxyConfiguration>>>
): String {
    val default = stringResource(R.string.default_value)
    return when (assignedId) {
        null -> default
        "DIRECT" -> stringResource(R.string.direct)
        "REJECT" -> stringResource(R.string.reject)
        else -> {
            val all = standaloneConfigs + subscribedGroups.flatMap { it.second }
            all.firstOrNull { it.id.toString() == assignedId }?.name ?: default
        }
    }
}

@Composable
private fun CustomRuleSetRow(
    name: String,
    ruleCount: Int,
    assignmentLabel: String,
    onOpen: () -> Unit,
    onDelete: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = Icons.AutoMirrored.Filled.Rule,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(32.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(text = name, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = stringResource(R.string.rules_count, ruleCount),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Text(
            text = assignmentLabel,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        IconButton(onClick = onDelete) {
            Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.delete))
        }
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun NewRuleSetDialog(
    onDismiss: () -> Unit,
    onCreate: (String) -> Unit
) {
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.new_rule_set)) },
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
                    if (trimmed.isNotEmpty()) onCreate(trimmed)
                },
                enabled = name.trim().isNotEmpty()
            ) { Text(stringResource(R.string.add)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RuleSetRow(
    ruleSet: RuleSetRepository.RuleSet,
    standaloneConfigs: List<ProxyConfiguration>,
    subscribedGroups: List<Pair<Subscription, List<ProxyConfiguration>>>,
    onAssign: (String?) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    val displayText = when (ruleSet.assignedConfigurationId) {
        null -> stringResource(R.string.default_value)
        "DIRECT" -> stringResource(R.string.direct)
        "REJECT" -> stringResource(R.string.reject)
        else -> {
            val allConfigs = standaloneConfigs + subscribedGroups.flatMap { it.second }
            allConfigs.find { it.id.toString() == ruleSet.assignedConfigurationId }?.name
                ?: stringResource(R.string.default_value)
        }
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AppIconView(name = ruleSet.name, modifier = Modifier.size(40.dp))
        Spacer(modifier = Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = ruleSet.name,
                style = MaterialTheme.typography.bodyLarge
            )

            ExposedDropdownMenuBox(
                expanded = expanded,
                onExpandedChange = { expanded = it }
            ) {
                OutlinedTextField(
                    value = displayText,
                    onValueChange = {},
                    readOnly = true,
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .menuAnchor(MenuAnchorType.PrimaryNotEditable),
                    textStyle = MaterialTheme.typography.bodySmall
                )
                ExposedDropdownMenu(
                    expanded = expanded,
                    onDismissRequest = { expanded = false }
                ) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.default_value)) },
                        onClick = {
                            onAssign(null)
                            expanded = false
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.direct)) },
                        onClick = {
                            onAssign("DIRECT")
                            expanded = false
                        }
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.reject)) },
                        onClick = {
                            onAssign("REJECT")
                            expanded = false
                        }
                    )

                    standaloneConfigs.forEach { config ->
                        DropdownMenuItem(
                            text = { Text(config.name) },
                            onClick = {
                                onAssign(config.id.toString())
                                expanded = false
                            }
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
                                onClick = {
                                    onAssign(config.id.toString())
                                    expanded = false
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}
