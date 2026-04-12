package com.argsment.anywhere.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

@Composable
fun PowerButton(
    isConnected: Boolean,
    isTransitioning: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val shadowColor by animateColorAsState(
        targetValue = if (isConnected) Color.Cyan.copy(alpha = 0.4f) else Color.Black.copy(alpha = 0.08f),
        animationSpec = tween(600),
        label = "shadowColor"
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier.size(160.dp)
    ) {
        Surface(
            shape = CircleShape,
            color = if (isConnected) Color.White.copy(alpha = 0.15f) else MaterialTheme.colorScheme.surfaceContainerHigh,
            modifier = Modifier
                .size(140.dp),
            onClick = onClick,
            enabled = enabled
        ) {
            Box(contentAlignment = Alignment.Center) {
                if (isTransitioning) {
                    CircularProgressIndicator(
                        color = if (isConnected) Color.White else MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(44.dp),
                        strokeWidth = 3.dp
                    )
                } else {
                    Icon(
                        imageVector = Icons.Filled.PowerSettingsNew,
                        contentDescription = null,
                        tint = if (isConnected) Color.White else MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(44.dp)
                    )
                }
            }
        }
    }
}
