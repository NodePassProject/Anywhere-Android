package com.argsment.anywhere.ui.proxy

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.data.model.OutboundProtocol
import com.argsment.anywhere.data.model.Subscription
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.network.SubscriptionFetcher
import kotlinx.coroutines.launch
import java.net.URL

private enum class ImportMethod(val titleResId: Int, val iconResId: Int) {
    QR_CODE(R.string.qr_code, android.R.drawable.ic_menu_camera),
    LINK(R.string.link, android.R.drawable.ic_menu_set_as),
    MANUAL(R.string.manual, android.R.drawable.ic_menu_edit);
}

/** Link type picker for https:// URLs — matches iOS AddProxyView's LinkType. */
private enum class LinkType(val titleResId: Int) {
    SUBSCRIPTION(R.string.subscription),
    HTTPS_PROXY(R.string.https_proxy),
    HTTP2_PROXY(R.string.http2_proxy);
}

@Composable
fun AddProxyScreen(
    onDismiss: () -> Unit,
    onShowManualAdd: () -> Unit,
    onImport: (ProxyConfiguration) -> Unit,
    onSubscriptionImport: (List<ProxyConfiguration>, Subscription) -> Unit,
    initialLink: String? = null
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // When opened via a deep link, start directly on the Link method with the URL pre-filled.
    var selectedMethod by remember { mutableStateOf<ImportMethod?>(if (initialLink != null) ImportMethod.LINK else null) }
    var linkURL by remember { mutableStateOf(initialLink ?: "") }
    var linkType by remember { mutableStateOf(LinkType.SUBSCRIPTION) }
    var isLoading by remember { mutableStateOf(false) }
    var showLinkError by remember { mutableStateOf(false) }
    var linkErrorMessage by remember { mutableStateOf("") }
    var showQrScanner by remember { mutableStateOf(false) }

    val isContinueDisabled = when (selectedMethod) {
        ImportMethod.LINK -> linkURL.isBlank() || isLoading
        null -> true
        else -> false
    }

    // Auto-paste from clipboard when link method selected
    LaunchedEffect(selectedMethod) {
        if (selectedMethod == ImportMethod.LINK && linkURL.isEmpty()) {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = clipboard.primaryClip?.getItemAt(0)?.text?.toString()?.trim()
            if (clip != null && (clip.startsWith("vless://") || clip.startsWith("ss://") || clip.startsWith("socks5://") || clip.startsWith("socks://") || clip.startsWith("naive+https://") || clip.startsWith("quic://") || clip.startsWith("http://") || clip.startsWith("https://"))) {
                linkURL = clip
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(20.dp)
    ) {
        // Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(R.string.add_proxy),
                style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.SemiBold),
                modifier = Modifier.weight(1f)
            )
            IconButton(onClick = onDismiss) {
                Icon(Icons.Default.Close, contentDescription = stringResource(R.string.cancel))
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Method picker
        ImportMethod.entries.forEach { method ->
            val isSelected = selectedMethod == method
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable {
                        selectedMethod = if (isSelected) null else method
                    }
                    .padding(vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    painter = painterResource(method.iconResId),
                    contentDescription = null,
                    modifier = Modifier.size(32.dp),
                    tint = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = stringResource(method.titleResId),
                    style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold),
                    modifier = Modifier.weight(1f)
                )
                RadioButton(
                    selected = isSelected,
                    onClick = { selectedMethod = if (isSelected) null else method }
                )
            }
        }

        // Link input field
        if (selectedMethod == ImportMethod.LINK) {
            Spacer(modifier = Modifier.height(12.dp))

            // Show link type picker when URL starts with http:// or https://
            // (matching iOS AddProxyView segmented picker)
            val trimmedUrl = linkURL.trim()
            if (trimmedUrl.startsWith("http://") || trimmedUrl.startsWith("https://")) {
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    LinkType.entries.forEachIndexed { index, type ->
                        SegmentedButton(
                            selected = linkType == type,
                            onClick = { linkType = type },
                            shape = SegmentedButtonDefaults.itemShape(index, LinkType.entries.size)
                        ) {
                            Text(stringResource(type.titleResId))
                        }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            OutlinedTextField(
                value = linkURL,
                onValueChange = { linkURL = it },
                label = { Text(stringResource(R.string.link)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = RoundedCornerShape(24.dp)
            )
            Text(
                text = stringResource(R.string.supports_proxy_link),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp, start = 8.dp)
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Continue button
        Button(
            onClick = {
                when (selectedMethod) {
                    ImportMethod.QR_CODE -> showQrScanner = true
                    ImportMethod.LINK -> {
                        val trimmed = linkURL.trim()
                        val isHTTP = trimmed.startsWith("http://") || trimmed.startsWith("https://")

                        if (trimmed.startsWith("vless://") || trimmed.startsWith("ss://") || trimmed.startsWith("socks5://") || trimmed.startsWith("socks://") || trimmed.startsWith("naive+https://") || trimmed.startsWith("quic://") ||
                            (isHTTP && linkType != LinkType.SUBSCRIPTION)) {
                            // Single proxy link (VLESS, Shadowsocks, NaiveProxy, QUIC,
                            // or HTTPS/HTTP2 proxy selected via the link type picker)
                            val naiveProtocol: OutboundProtocol? = when (linkType) {
                                LinkType.HTTPS_PROXY -> OutboundProtocol.NAIVE_HTTP11
                                LinkType.HTTP2_PROXY -> OutboundProtocol.NAIVE_HTTP2
                                LinkType.SUBSCRIPTION -> null
                            }
                            try {
                                val config = ProxyConfiguration.fromUrl(trimmed, naiveProtocol)
                                onImport(config)
                            } catch (e: Exception) {
                                linkErrorMessage = e.message ?: context.getString(R.string.invalid_url)
                                showLinkError = true
                            }
                        } else {
                            // Subscription URL
                            isLoading = true
                            scope.launch {
                                try {
                                    val result = SubscriptionFetcher.fetch(trimmed)
                                    val name = result.name
                                        ?: runCatching { URL(trimmed).host }.getOrNull()
                                        ?: context.getString(R.string.subscription)
                                    val subscription = Subscription(
                                        name = name,
                                        url = trimmed,
                                        lastUpdate = System.currentTimeMillis(),
                                        upload = result.upload,
                                        download = result.download,
                                        total = result.total,
                                        expire = result.expire
                                    )
                                    onSubscriptionImport(result.configurations, subscription)
                                } catch (e: Exception) {
                                    linkErrorMessage = e.message ?: context.getString(R.string.import_failed)
                                    showLinkError = true
                                }
                                isLoading = false
                            }
                        }
                    }
                    ImportMethod.MANUAL -> {
                        onShowManualAdd()
                    }
                    null -> {}
                }
            },
            enabled = !isContinueDisabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(24.dp)
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary
                )
            } else {
                Text(
                    text = stringResource(R.string.continue_action),
                    style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold)
                )
            }
        }
    }

    // QR Scanner
    if (showQrScanner) {
        // Navigate to QR scanner - will be a full screen composable
        com.argsment.anywhere.ui.scanner.QrScannerScreen(
            onResult = { code ->
                showQrScanner = false
                val trimmed = code.trim()
                if (trimmed.startsWith("vless://") || trimmed.startsWith("ss://") || trimmed.startsWith("socks5://") || trimmed.startsWith("socks://") || trimmed.startsWith("naive+https://") || trimmed.startsWith("quic://")) {
                    try {
                        val config = ProxyConfiguration.fromUrl(trimmed)
                        onImport(config)
                    } catch (e: Exception) {
                        linkErrorMessage = e.message ?: context.getString(R.string.invalid_qr_code)
                        showLinkError = true
                    }
                } else {
                    linkErrorMessage = context.getString(R.string.qr_code_not_supported)
                    showLinkError = true
                }
            },
            onDismiss = { showQrScanner = false }
        )
    }

    // Error dialog
    if (showLinkError) {
        AlertDialog(
            onDismissRequest = { showLinkError = false },
            title = { Text(stringResource(R.string.import_failed)) },
            text = { Text(linkErrorMessage) },
            confirmButton = {
                TextButton(onClick = { showLinkError = false }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}
