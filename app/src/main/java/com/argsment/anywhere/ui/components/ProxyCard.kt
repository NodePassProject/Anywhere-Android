package com.argsment.anywhere.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.data.model.VlessConfiguration
import com.argsment.anywhere.data.network.LatencyResult

@Composable
fun ProxyCardContent(
    configuration: VlessConfiguration,
    isSelected: Boolean,
    latency: LatencyResult?,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = configuration.name,
                    style = MaterialTheme.typography.bodyLarge
                )
                if (isSelected) {
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "\u2713",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }
            Text(
                text = "${configuration.serverAddress}:${configuration.serverPort}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1
            )
            Row {
                Text(
                    text = configuration.transport.uppercase(),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
                Text(
                    text = " \u00B7 ",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
                Text(
                    text = configuration.security.uppercase(),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
                if (configuration.flow?.contains("vision") == true) {
                    Text(
                        text = " \u00B7 Vision",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                    )
                }
            }
        }

        LatencyBadge(latency = latency)
    }
}

@Composable
fun LatencyBadge(latency: LatencyResult?, modifier: Modifier = Modifier) {
    when (latency) {
        is LatencyResult.Testing -> {
            CircularProgressIndicator(
                modifier = modifier.width(20.dp),
                strokeWidth = 2.dp
            )
        }
        is LatencyResult.Success -> {
            val color = when {
                latency.ms < 300 -> Color(0xFF4CAF50) // green
                latency.ms < 600 -> Color(0xFFFF9800) // yellow/orange
                else -> Color(0xFFF44336) // red
            }
            Text(
                text = stringResource(R.string.latency_ms, latency.ms),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = color,
                modifier = modifier
            )
        }
        is LatencyResult.Failed -> {
            Text(
                text = stringResource(R.string.timeout),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = modifier
            )
        }
        null -> { /* no latency result yet */ }
    }
}
