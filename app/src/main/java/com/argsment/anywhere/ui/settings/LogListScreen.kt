package com.argsment.anywhere.ui.settings

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.PopupProperties
import androidx.lifecycle.viewmodel.compose.viewModel
import com.argsment.anywhere.R
import com.argsment.anywhere.viewmodel.LogsModel
import kotlinx.coroutines.flow.StateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import androidx.compose.runtime.collectAsState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogListScreen(
    onBack: () -> Unit,
    logsModel: LogsModel = viewModel()
) {
    val context = LocalContext.current
    val logs by logsModel.logs.collectAsState()

    var selectMode by remember { mutableStateOf(false) }
    val selection = remember { mutableStateMapOf<UUID, Unit>() }

    DisposableEffect(Unit) {
        logsModel.startPolling()
        onDispose { logsModel.stopPolling() }
    }

    // Toggling select mode pauses polling so the list doesn't shift while picking.
    LaunchedEffect(selectMode) {
        if (selectMode) {
            logsModel.stopPolling(clearLogs = false)
        } else {
            logsModel.startPolling()
            selection.clear()
        }
    }

    BackHandler {
        if (selectMode) selectMode = false else onBack()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.logs)) },
                navigationIcon = {
                    IconButton(onClick = { if (selectMode) selectMode = false else onBack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                actions = {
                    if (selectMode) {
                        val label = if (selection.isEmpty()) {
                            stringResource(R.string.cancel)
                        } else {
                            stringResource(R.string.copy_count, selection.size)
                        }
                        TextButton(onClick = {
                            if (selection.isEmpty()) {
                                selectMode = false
                            } else {
                                copyToClipboard(
                                    context,
                                    logs.filter { selection.contains(it.id) }.joinToString("\n") { it.formatted() }
                                )
                                selection.clear()
                                selectMode = false
                            }
                        }) { Text(label) }
                    } else {
                        TextButton(onClick = { selectMode = true }) {
                            Text(stringResource(R.string.select))
                        }
                    }
                }
            )
        }
    ) { innerPadding ->
        if (logs.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Filled.CheckCircle,
                        contentDescription = null,
                        modifier = Modifier.size(56.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.size(12.dp))
                    Text(
                        stringResource(R.string.no_recent_logs),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 4.dp)
            ) {
                // Newest first.
                val reversed = logs.asReversed()
                items(reversed, key = { it.id }) { entry ->
                    LogRow(
                        entry = entry,
                        selectMode = selectMode,
                        selected = selection.contains(entry.id),
                        onToggleSelect = {
                            if (selection.contains(entry.id)) selection.remove(entry.id)
                            else selection[entry.id] = Unit
                        },
                        onCopy = { copyToClipboard(context, entry.formatted()) }
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
                }
            }
        }
    }
}

@Composable
private fun LogRow(
    entry: LogsModel.LogEntry,
    selectMode: Boolean,
    selected: Boolean,
    onToggleSelect: () -> Unit,
    onCopy: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier
            .fillMaxSize()
            .then(
                if (selectMode) {
                    Modifier
                        .clickable { onToggleSelect() }
                        .background(
                            if (selected) MaterialTheme.colorScheme.secondaryContainer
                            else Color.Transparent
                        )
                } else {
                    Modifier.clickable { showMenu = true }
                }
            )
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            imageVector = entry.level.icon(),
            contentDescription = null,
            tint = entry.level.color(),
            modifier = Modifier
                .size(16.dp)
                .padding(top = 2.dp)
        )

        Column(modifier = Modifier.padding(start = 4.dp)) {
            Text(
                text = entry.message,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp
                )
            )
            Spacer(Modifier.size(2.dp))
            Text(
                text = formatTime(entry.timestamp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            DropdownMenu(
                expanded = showMenu,
                onDismissRequest = { showMenu = false },
                properties = PopupProperties(focusable = true)
            ) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.copy)) },
                    onClick = {
                        onCopy()
                        showMenu = false
                    }
                )
            }
        }
    }
}

private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("Anywhere Logs", text))
}

private val timeFormatter = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

private fun formatTime(timestampMs: Long): String = timeFormatter.format(Date(timestampMs))

private fun LogsModel.LogEntry.formatted(): String {
    val time = formatTime(timestamp)
    val levelStr = when (level) {
        LogsModel.LogLevel.info -> "INFO"
        LogsModel.LogLevel.warning -> "WARN"
        LogsModel.LogLevel.error -> "ERROR"
    }
    return "$time [$levelStr] $message"
}

@Composable
private fun LogsModel.LogLevel.icon() = when (this) {
    LogsModel.LogLevel.info -> Icons.Filled.Info
    LogsModel.LogLevel.warning -> Icons.Filled.Warning
    LogsModel.LogLevel.error -> Icons.Filled.Error
}

@Composable
private fun LogsModel.LogLevel.color(): Color = when (this) {
    LogsModel.LogLevel.info -> MaterialTheme.colorScheme.onSurfaceVariant
    LogsModel.LogLevel.warning -> Color(0xFFFF9800)
    LogsModel.LogLevel.error -> Color(0xFFF44336)
}
