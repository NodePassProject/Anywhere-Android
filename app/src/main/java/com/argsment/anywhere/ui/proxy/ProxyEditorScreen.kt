package com.argsment.anywhere.ui.proxy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
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
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.argsment.anywhere.R
import com.argsment.anywhere.data.model.HttpUpgradeConfiguration
import com.argsment.anywhere.data.model.HysteriaUploadMbpsDefault
import com.argsment.anywhere.data.model.HysteriaUploadMbpsRange
import com.argsment.anywhere.data.model.NaiveProtocol
import com.argsment.anywhere.data.model.OutboundProtocol
import com.argsment.anywhere.data.model.clampHysteriaUploadMbps
import com.argsment.anywhere.data.model.RealityConfiguration
import com.argsment.anywhere.data.model.TlsConfiguration
import com.argsment.anywhere.data.model.TlsFingerprint
import com.argsment.anywhere.data.model.TlsVersion
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.model.WebSocketConfiguration
import com.argsment.anywhere.data.model.XHttpConfiguration
import com.argsment.anywhere.data.model.XHttpMode
import com.argsment.anywhere.vpn.util.base64UrlToByteArrayOrNull
import com.argsment.anywhere.vpn.util.hexToByteArrayOrNull
import com.argsment.anywhere.vpn.util.toBase64Url
import com.argsment.anywhere.vpn.util.toHex
import java.util.UUID

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProxyEditorScreen(
    configuration: ProxyConfiguration?,
    onSave: (ProxyConfiguration) -> Unit,
    onDismiss: () -> Unit
) {
    var selectedProtocol by remember { mutableStateOf(OutboundProtocol.VLESS) }
    var name by remember { mutableStateOf("") }
    var serverAddress by remember { mutableStateOf("") }
    var serverPort by remember { mutableStateOf("") }
    var uuid by remember { mutableStateOf("") }
    var encryption by remember { mutableStateOf("none") }
    var transport by remember { mutableStateOf("tcp") }
    var flow by remember { mutableStateOf("") }
    var security by remember { mutableStateOf("none") }

    // WebSocket fields
    var wsHost by remember { mutableStateOf("") }
    var wsPath by remember { mutableStateOf("/") }

    // HTTPUpgrade fields
    var httpUpgradeHost by remember { mutableStateOf("") }
    var httpUpgradePath by remember { mutableStateOf("/") }

    // XHTTP fields
    var xhttpHost by remember { mutableStateOf("") }
    var xhttpPath by remember { mutableStateOf("/") }
    var xhttpMode by remember { mutableStateOf("auto") }
    var xhttpExtra by remember { mutableStateOf("") }

    // TLS fields
    var tlsSNI by remember { mutableStateOf("") }
    var tlsALPN by remember { mutableStateOf("") }
    var tlsAllowInsecure by remember { mutableStateOf(false) }
    var tlsMinVersion by remember { mutableStateOf<TlsVersion?>(null) }
    var tlsMaxVersion by remember { mutableStateOf<TlsVersion?>(null) }

    // Mux + XUDP
    var muxEnabled by remember { mutableStateOf(true) }
    var xudpEnabled by remember { mutableStateOf(true) }

    // Reality fields
    var sni by remember { mutableStateOf("") }
    var publicKey by remember { mutableStateOf("") }
    var shortId by remember { mutableStateOf("") }
    var fingerprint by remember { mutableStateOf(TlsFingerprint.CHROME_133) }

    // Shadowsocks fields
    var ssPassword by remember { mutableStateOf("") }
    var ssMethod by remember { mutableStateOf("aes-128-gcm") }

    // Naive fields
    var naiveUsername by remember { mutableStateOf("") }
    var naivePassword by remember { mutableStateOf("") }

    // SOCKS5 fields
    var socks5Username by remember { mutableStateOf("") }
    var socks5Password by remember { mutableStateOf("") }

    // Hysteria fields. Matches iOS ProxyEditorView which only edits password +
    // uploadMbps. SNI/insecure flags stay on the original config's TLS blob.
    var hysteriaPassword by remember { mutableStateOf("") }
    var hysteriaUploadMbpsText by remember { mutableStateOf(HysteriaUploadMbpsDefault.toString()) }

    val isShadowsocks = selectedProtocol == OutboundProtocol.SHADOWSOCKS
    val isSocks5 = selectedProtocol == OutboundProtocol.SOCKS5
    val isNaive = selectedProtocol.isNaive
    val isHysteria = selectedProtocol == OutboundProtocol.HYSTERIA
    val isReality = security == "reality"
    val isTLS = security == "tls"

    val isValid = name.isNotEmpty() &&
            serverAddress.isNotEmpty() &&
            serverPort.toUShortOrNull() != null &&
            when {
                isNaive -> naiveUsername.isNotEmpty() && naivePassword.isNotEmpty()
                isShadowsocks -> ssPassword.isNotEmpty()
                isSocks5 -> true  // SOCKS5 username/password are optional
                isHysteria -> hysteriaPassword.isNotEmpty() &&
                        (hysteriaUploadMbpsText.toIntOrNull()
                            ?.let { it in HysteriaUploadMbpsRange } == true)
                else -> runCatching { UUID.fromString(uuid) }.isSuccess &&
                        (!isReality || (sni.isNotEmpty() && publicKey.isNotEmpty()))
            }

    LaunchedEffect(configuration) {
        configuration?.let { config ->
            selectedProtocol = config.outboundProtocol
            name = config.name
            serverAddress = config.serverAddress
            serverPort = config.serverPort.toString()
            uuid = config.uuid.toString()
            encryption = config.encryption
            transport = config.transport
            flow = config.flow ?: ""
            security = config.security
            config.websocket?.let {
                wsHost = it.host
                wsPath = it.path
            }
            config.httpUpgrade?.let {
                httpUpgradeHost = it.host
                httpUpgradePath = it.path
            }
            config.xhttp?.let {
                xhttpHost = it.host
                xhttpPath = it.path
                xhttpMode = it.mode.raw
                xhttpExtra = it.toExtraJson()
            }
            muxEnabled = config.muxEnabled
            xudpEnabled = config.xudpEnabled
            config.tls?.let {
                tlsSNI = it.serverName
                tlsALPN = it.alpn?.joinToString(",") ?: ""
                tlsAllowInsecure = it.allowInsecure
                fingerprint = it.fingerprint
                tlsMinVersion = it.minVersion
                tlsMaxVersion = it.maxVersion
            }
            config.reality?.let {
                sni = it.serverName
                publicKey = it.publicKey.toBase64Url()
                shortId = it.shortId.toHex()
                fingerprint = it.fingerprint
            }
            ssPassword = config.ssPassword ?: ""
            ssMethod = config.ssMethod ?: "aes-128-gcm"
            naiveUsername = config.naiveUsername ?: ""
            naivePassword = config.naivePassword ?: ""
            socks5Username = config.socks5Username ?: ""
            socks5Password = config.socks5Password ?: ""
            hysteriaPassword = config.hysteriaPassword ?: ""
            hysteriaUploadMbpsText =
                (config.hysteriaUploadMbps ?: HysteriaUploadMbpsDefault).toString()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        if (configuration != null) stringResource(R.string.edit_configuration)
                        else stringResource(R.string.add_configuration)
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = stringResource(R.string.cancel))
                    }
                },
                actions = {
                    IconButton(onClick = {
                        val port = serverPort.toUShortOrNull() ?: return@IconButton
                        val needsUuid =
                            !(isShadowsocks || isNaive || isSocks5 || isHysteria)
                        val parsedUUID = if (!needsUuid) {
                            configuration?.uuid ?: UUID.randomUUID()
                        } else {
                            runCatching { UUID.fromString(uuid) }.getOrNull() ?: return@IconButton
                        }

                        var tlsConfiguration: TlsConfiguration? = null
                        if (isTLS && !isNaive && !isHysteria) {
                            val resolvedSNI = tlsSNI.ifEmpty { serverAddress }
                            val alpn = tlsALPN.takeIf { it.isNotEmpty() }?.split(",")
                            tlsConfiguration = TlsConfiguration(
                                serverName = resolvedSNI,
                                alpn = alpn,
                                allowInsecure = tlsAllowInsecure,
                                fingerprint = fingerprint,
                                minVersion = tlsMinVersion,
                                maxVersion = tlsMaxVersion
                            )
                        }

                        // Hysteria: preserve the original TLS blob (which carries
                        // SNI/insecure flags populated by URL import). The editor
                        // itself doesn't expose those knobs — matching iOS, which
                        // only edits password + upload Mbps for Hysteria.
                        if (isHysteria) {
                            tlsConfiguration = configuration?.tls
                        }

                        var realityConfiguration: RealityConfiguration? = null
                        if (isReality && !isNaive && !isShadowsocks && !isSocks5 && !isHysteria) {
                            val pk = publicKey.base64UrlToByteArrayOrNull() ?: return@IconButton
                            val sid = shortId.hexToByteArrayOrNull() ?: byteArrayOf()
                            realityConfiguration = RealityConfiguration(
                                serverName = sni,
                                publicKey = pk,
                                shortId = sid,
                                fingerprint = fingerprint
                            )
                        }

                        var wsConfiguration: WebSocketConfiguration? = null
                        if (transport == "ws" && !isNaive && !isSocks5 && !isHysteria) {
                            val host = wsHost.ifEmpty { serverAddress }
                            wsConfiguration = WebSocketConfiguration(host = host, path = wsPath)
                        }

                        var httpUpgradeConfiguration: HttpUpgradeConfiguration? = null
                        if (transport == "httpupgrade" && !isNaive && !isSocks5 && !isHysteria) {
                            val host = httpUpgradeHost.ifEmpty { serverAddress }
                            httpUpgradeConfiguration = HttpUpgradeConfiguration(host = host, path = httpUpgradePath)
                        }

                        var xhttpConfiguration: XHttpConfiguration? = null
                        if (transport == "xhttp" && !isNaive && !isSocks5 && !isHysteria) {
                            val host = xhttpHost.ifEmpty { serverAddress }
                            val mode = XHttpMode.fromRaw(xhttpMode)
                            xhttpConfiguration = XHttpConfiguration.fromExtraJson(
                                host = host, path = xhttpPath, mode = mode, extraJson = xhttpExtra
                            )
                        }

                        val bareAddress = if (serverAddress.startsWith("[") && serverAddress.endsWith("]"))
                            serverAddress.drop(1).dropLast(1) else serverAddress

                        val naiveProto = when (selectedProtocol) {
                            OutboundProtocol.NAIVE_HTTP11 -> NaiveProtocol.HTTP11
                            OutboundProtocol.NAIVE_HTTP2 -> NaiveProtocol.HTTP2
                            OutboundProtocol.NAIVE_HTTP3 -> NaiveProtocol.HTTP2 // placeholder
                            else -> null
                        }

                        val hysteriaMbps = if (isHysteria) {
                            clampHysteriaUploadMbps(
                                hysteriaUploadMbpsText.toIntOrNull() ?: HysteriaUploadMbpsDefault
                            )
                        } else null

                        val config = ProxyConfiguration(
                            id = configuration?.id ?: UUID.randomUUID(),
                            name = name,
                            serverAddress = bareAddress,
                            serverPort = port,
                            uuid = parsedUUID,
                            encryption = if (isShadowsocks || isNaive || isSocks5 || isHysteria) "none" else encryption,
                            transport = if (isNaive || isSocks5 || isHysteria) "tcp" else transport,
                            flow = if (isShadowsocks || isNaive || isSocks5 || isHysteria) null else flow.ifEmpty { null },
                            security = if (isNaive || isHysteria) "none" else security,
                            tls = tlsConfiguration,
                            reality = realityConfiguration,
                            websocket = wsConfiguration,
                            httpUpgrade = httpUpgradeConfiguration,
                            xhttp = xhttpConfiguration,
                            muxEnabled = if (isShadowsocks || isNaive || isSocks5 || isHysteria) false else muxEnabled,
                            xudpEnabled = if (isShadowsocks || isNaive || isSocks5 || isHysteria) false else xudpEnabled,
                            subscriptionId = configuration?.subscriptionId,
                            outboundProtocol = selectedProtocol,
                            ssPassword = if (isShadowsocks) ssPassword else null,
                            ssMethod = if (isShadowsocks) ssMethod else null,
                            socks5Username = if (isSocks5) socks5Username.ifEmpty { null } else null,
                            socks5Password = if (isSocks5) socks5Password.ifEmpty { null } else null,
                            naiveUsername = if (isNaive) naiveUsername else null,
                            naivePassword = if (isNaive) naivePassword else null,
                            naiveProtocol = naiveProto,
                            hysteriaPassword = if (isHysteria) hysteriaPassword else null,
                            hysteriaUploadMbps = hysteriaMbps,
                            // Preserve the original testseed — matches iOS which reads
                            // self.configuration?.testseed rather than resetting to default.
                            testseed = configuration?.testseed ?: listOf(900u, 500u, 900u, 256u)
                        )
                        onSave(config)
                    }, enabled = isValid) {
                        Icon(Icons.Default.Check, contentDescription = stringResource(R.string.save))
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Name section
            SectionHeader(stringResource(R.string.name))
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.name)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            // Protocol picker. Order mirrors iOS ProxyEditorView so users see
            // the same list across platforms.
            SectionHeader(stringResource(R.string.protocol_label))
            DropdownField(
                label = stringResource(R.string.protocol_label),
                selectedValue = selectedProtocol.name,
                options = listOf(
                    OutboundProtocol.VLESS.name to "VLESS",
                    OutboundProtocol.HYSTERIA.name to "Hysteria",
                    OutboundProtocol.SHADOWSOCKS.name to "Shadowsocks",
                    OutboundProtocol.SOCKS5.name to "SOCKS5",
                    OutboundProtocol.NAIVE_HTTP11.name to "HTTPS",
                    OutboundProtocol.NAIVE_HTTP2.name to "HTTP2",
                    OutboundProtocol.NAIVE_HTTP3.name to "QUIC"
                ),
                onSelect = { value ->
                    selectedProtocol = OutboundProtocol.valueOf(value)
                    if (isShadowsocks || isSocks5 || isHysteria || selectedProtocol.isNaive) {
                        flow = ""
                        if (security == "reality") security = "none"
                    }
                }
            )

            // Server section
            SectionHeader(stringResource(R.string.server))
            OutlinedTextField(
                value = serverAddress,
                onValueChange = { serverAddress = it },
                label = { Text(stringResource(R.string.address)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
            )
            OutlinedTextField(
                value = serverPort,
                onValueChange = { serverPort = it },
                label = { Text(stringResource(R.string.port)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
            )

            // Protocol-specific credential fields
            if (isNaive) {
                OutlinedTextField(
                    value = naiveUsername,
                    onValueChange = { naiveUsername = it },
                    label = { Text(stringResource(R.string.username)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                OutlinedTextField(
                    value = naivePassword,
                    onValueChange = { naivePassword = it },
                    label = { Text(stringResource(R.string.password)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation()
                )
            } else if (isSocks5) {
                OutlinedTextField(
                    value = socks5Username,
                    onValueChange = { socks5Username = it },
                    label = { Text(stringResource(R.string.username)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                OutlinedTextField(
                    value = socks5Password,
                    onValueChange = { socks5Password = it },
                    label = { Text(stringResource(R.string.password)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation()
                )
            } else if (isShadowsocks) {
                OutlinedTextField(
                    value = ssPassword,
                    onValueChange = { ssPassword = it },
                    label = { Text(stringResource(R.string.password)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation()
                )
                DropdownField(
                    label = stringResource(R.string.method),
                    selectedValue = ssMethod,
                    options = listOf(
                        "none" to stringResource(R.string.none),
                        "aes-128-gcm" to "AES-128-GCM",
                        "aes-256-gcm" to "AES-256-GCM",
                        "chacha20-ietf-poly1305" to "ChaCha20-Poly1305",
                        "2022-blake3-aes-128-gcm" to "BLAKE3-AES-128-GCM",
                        "2022-blake3-aes-256-gcm" to "BLAKE3-AES-256-GCM",
                        "2022-blake3-chacha20-poly1305" to "BLAKE3-ChaCha20-Poly1305"
                    ),
                    onSelect = { ssMethod = it }
                )
            } else if (isHysteria) {
                // Matches iOS ProxyEditorView: Hysteria exposes only a password
                // and an upload-bandwidth field; SNI is preserved from the
                // original config (populated via URL import) but not edited here.
                OutlinedTextField(
                    value = hysteriaPassword,
                    onValueChange = { hysteriaPassword = it },
                    label = { Text(stringResource(R.string.password)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation()
                )
                OutlinedTextField(
                    value = hysteriaUploadMbpsText,
                    onValueChange = { new ->
                        hysteriaUploadMbpsText = new.filter { it.isDigit() }
                    },
                    label = { Text(stringResource(R.string.upload_mbps)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                )
            } else {
                // VLESS fields
                OutlinedTextField(
                    value = uuid,
                    onValueChange = { uuid = it },
                    label = { Text("UUID") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                DropdownField(
                    label = stringResource(R.string.encryption),
                    selectedValue = encryption,
                    options = listOf("none" to stringResource(R.string.none)),
                    onSelect = { encryption = it }
                )
            }

            // Transport section (not for Naive, SOCKS5, or Hysteria — Hysteria
            // always runs over QUIC with no user-selectable transport.)
            if (!isNaive && !isSocks5 && !isHysteria) {
                SectionHeader(stringResource(R.string.transport))
                DropdownField(
                    label = stringResource(R.string.transport),
                    selectedValue = transport,
                    options = listOf(
                        "tcp" to "TCP",
                        "ws" to "WebSocket",
                        "httpupgrade" to "HTTPUpgrade",
                        "xhttp" to "XHTTP"
                    ),
                    onSelect = {
                        transport = it
                        if (flow.isNotEmpty() && it != "tcp") flow = ""
                    }
                )

                if (transport == "ws") {
                    OutlinedTextField(
                        value = wsHost,
                        onValueChange = { wsHost = it },
                        label = { Text(stringResource(R.string.host)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = wsPath,
                        onValueChange = { wsPath = it },
                        label = { Text(stringResource(R.string.path)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }

                if (transport == "httpupgrade") {
                    OutlinedTextField(
                        value = httpUpgradeHost,
                        onValueChange = { httpUpgradeHost = it },
                        label = { Text(stringResource(R.string.host)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = httpUpgradePath,
                        onValueChange = { httpUpgradePath = it },
                        label = { Text(stringResource(R.string.path)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }

                if (transport == "xhttp") {
                    OutlinedTextField(
                        value = xhttpHost,
                        onValueChange = { xhttpHost = it },
                        label = { Text(stringResource(R.string.host)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = xhttpPath,
                        onValueChange = { xhttpPath = it },
                        label = { Text(stringResource(R.string.path)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    DropdownField(
                        label = stringResource(R.string.mode),
                        selectedValue = xhttpMode,
                        options = listOf(
                            "auto" to stringResource(R.string.auto),
                            "packet-up" to "Packet Up",
                            "stream-up" to "Stream Up",
                            "stream-one" to "Stream One"
                        ),
                        onSelect = { xhttpMode = it }
                    )
                    OutlinedTextField(
                        value = xhttpExtra,
                        onValueChange = { xhttpExtra = it },
                        label = { Text("Extra (JSON)") },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 2,
                        maxLines = 6
                    )
                }

                if (!isShadowsocks && transport == "tcp") {
                    DropdownField(
                        label = stringResource(R.string.flow),
                        selectedValue = flow,
                        options = listOf(
                            "" to stringResource(R.string.none),
                            "xtls-rprx-vision" to "Vision",
                            "xtls-rprx-vision-udp443" to "Vision with UDP 443"
                        ),
                        onSelect = { flow = it }
                    )
                    SwitchRow(
                        label = "Mux",
                        checked = muxEnabled,
                        onCheckedChange = {
                            muxEnabled = it
                            if (!it) xudpEnabled = false
                        }
                    )
                    if (muxEnabled) {
                        SwitchRow(
                            label = "XUDP",
                            checked = xudpEnabled,
                            onCheckedChange = { xudpEnabled = it }
                        )
                    }
                }
            }

            // TLS section (not for Naive, SOCKS5, or Hysteria — Hysteria's
            // QUIC handshake carries its own TLS internally, so there's nothing
            // for the user to configure here.)
            if (!isNaive && !isSocks5 && !isHysteria) {
                SectionHeader("TLS")
                DropdownField(
                    label = stringResource(R.string.security),
                    selectedValue = security,
                    options = if (isShadowsocks) {
                        listOf(
                            "none" to stringResource(R.string.none),
                            "tls" to "TLS"
                        )
                    } else {
                        listOf(
                            "none" to stringResource(R.string.none),
                            "tls" to "TLS",
                            "reality" to "Reality"
                        )
                    },
                    onSelect = { security = it }
                )

                if (isTLS) {
                    OutlinedTextField(
                        value = tlsSNI,
                        onValueChange = { tlsSNI = it },
                        label = { Text("SNI") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = tlsALPN,
                        onValueChange = { tlsALPN = it },
                        label = { Text("ALPN") },
                        placeholder = { Text("h2,http/1.1") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    SwitchRow(
                        label = stringResource(R.string.allow_insecure),
                        checked = tlsAllowInsecure,
                        onCheckedChange = { tlsAllowInsecure = it }
                    )
                    FingerprintDropdown(
                        selected = fingerprint,
                        onSelect = { fingerprint = it }
                    )
                    DropdownField(
                        label = "Min Version",
                        selectedValue = tlsMinVersion?.name ?: "ANY",
                        options = listOf(
                            "ANY" to "Any",
                            TlsVersion.TLS12.name to "TLS 1.2",
                            TlsVersion.TLS13.name to "TLS 1.3"
                        ),
                        onSelect = { value ->
                            tlsMinVersion = if (value == "ANY") null else TlsVersion.valueOf(value)
                        }
                    )
                    DropdownField(
                        label = "Max Version",
                        selectedValue = tlsMaxVersion?.name ?: "ANY",
                        options = listOf(
                            "ANY" to "Any",
                            TlsVersion.TLS12.name to "TLS 1.2",
                            TlsVersion.TLS13.name to "TLS 1.3"
                        ),
                        onSelect = { value ->
                            tlsMaxVersion = if (value == "ANY") null else TlsVersion.valueOf(value)
                        }
                    )
                }

                if (isReality) {
                    OutlinedTextField(
                        value = sni,
                        onValueChange = { sni = it },
                        label = { Text("SNI") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = publicKey,
                        onValueChange = { publicKey = it },
                        label = { Text(stringResource(R.string.public_key)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = shortId,
                        onValueChange = { shortId = it },
                        label = { Text("Short ID") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    FingerprintDropdown(
                        selected = fingerprint,
                        onSelect = { fingerprint = it }
                    )
                }
            }

            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 8.dp)
    )
}

@Composable
private fun SwitchRow(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyLarge)
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DropdownField(
    label: String,
    selectedValue: String,
    options: List<Pair<String, String>>,
    onSelect: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val displayText = options.find { it.first == selectedValue }?.second ?: selectedValue

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it }
    ) {
        OutlinedTextField(
            value = displayText,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable)
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            options.forEach { (value, display) ->
                DropdownMenuItem(
                    text = { Text(display) },
                    onClick = {
                        onSelect(value)
                        expanded = false
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FingerprintDropdown(
    selected: TlsFingerprint,
    onSelect: (TlsFingerprint) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it }
    ) {
        OutlinedTextField(
            value = selected.displayName,
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.fingerprint)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable)
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            TlsFingerprint.entries.forEach { fp ->
                DropdownMenuItem(
                    text = { Text(fp.displayName) },
                    onClick = {
                        onSelect(fp)
                        expanded = false
                    }
                )
            }
        }
    }
}
