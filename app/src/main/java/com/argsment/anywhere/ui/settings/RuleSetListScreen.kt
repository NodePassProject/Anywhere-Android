package com.argsment.anywhere.ui.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.material3.Text
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
import com.argsment.anywhere.data.model.VlessConfiguration
import com.argsment.anywhere.data.repository.RuleSetRepository
import com.argsment.anywhere.ui.components.AppIconView
import com.argsment.anywhere.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RuleSetListScreen(
    viewModel: VpnViewModel,
    onBack: () -> Unit
) {
    val ruleSets by viewModel.ruleSetRepository.ruleSets.collectAsState()
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()

    val standaloneConfigs = remember(configurations) {
        configurations.filter { it.subscriptionId == null }
    }

    val subscribedGroups = remember(configurations, subscriptions) {
        subscriptions.mapNotNull { subscription ->
            val configs = configurations.filter { it.subscriptionId == subscription.id }
            if (configs.isEmpty()) null else subscription to configs
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.routing_rules)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
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
            items(ruleSets, key = { it.id }) { ruleSet ->
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
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RuleSetRow(
    ruleSet: RuleSetRepository.RuleSet,
    standaloneConfigs: List<VlessConfiguration>,
    subscribedGroups: List<Pair<Subscription, List<VlessConfiguration>>>,
    onAssign: (String?) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    val displayText = when (ruleSet.assignedConfigurationId) {
        null -> stringResource(R.string.default_value)
        "DIRECT" -> stringResource(R.string.direct)
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

                    // Standalone configs
                    standaloneConfigs.forEach { config ->
                        DropdownMenuItem(
                            text = { Text(config.name) },
                            onClick = {
                                onAssign(config.id.toString())
                                expanded = false
                            }
                        )
                    }

                    // Subscribed configs
                    subscribedGroups.forEach { (subscription, configs) ->
                        // Subscription header (non-clickable)
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
