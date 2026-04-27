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
import com.argsment.anywhere.data.model.NaiveProtocol
import com.argsment.anywhere.data.model.OutboundProtocol
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

    var wsHost by remember { mutableStateOf("") }
    var wsPath by remember { mutableStateOf("/") }

    var httpUpgradeHost by remember { mutableStateOf("") }
    var httpUpgradePath by remember { mutableStateOf("/") }

    var xhttpHost by remember { mutableStateOf("") }
    var xhttpPath by remember { mutableStateOf("/") }
    var xhttpMode by remember { mutableStateOf("auto") }
    var xhttpExtra by remember { mutableStateOf("") }
    var grpcServiceName by remember { mutableStateOf("") }
    var grpcAuthority by remember { mutableStateOf("") }
    var grpcMultiMode by remember { mutableStateOf(false) }
    var grpcUserAgent by remember { mutableStateOf("") }

    var tlsSNI by remember { mutableStateOf("") }
    var tlsALPN by remember { mutableStateOf("") }
    var tlsAllowInsecure by remember { mutableStateOf(false) }
    var tlsMinVersion by remember { mutableStateOf<TlsVersion?>(null) }
    var tlsMaxVersion by remember { mutableStateOf<TlsVersion?>(null) }

    var muxEnabled by remember { mutableStateOf(true) }
    var xudpEnabled by remember { mutableStateOf(true) }

    var sni by remember { mutableStateOf("") }
    var publicKey by remember { mutableStateOf("") }
    var shortId by remember { mutableStateOf("") }
    var fingerprint by remember { mutableStateOf(TlsFingerprint.CHROME_133) }

    var ssPassword by remember { mutableStateOf("") }
    var ssMethod by remember { mutableStateOf("aes-128-gcm") }

    var naiveUsername by remember { mutableStateOf("") }
    var naivePassword by remember { mutableStateOf("") }

    var socks5Username by remember { mutableStateOf("") }
    var socks5Password by remember { mutableStateOf("") }

    // Trojan: password lives here; TLS knobs reuse the shared
    // tlsSNI/tlsALPN/fingerprint state.
    var trojanPassword by remember { mutableStateOf("") }

    val isShadowsocks = selectedProtocol == OutboundProtocol.SHADOWSOCKS
    val isSocks5 = selectedProtocol == OutboundProtocol.SOCKS5
    val isNaive = selectedProtocol.isNaive
    val isTrojan = selectedProtocol == OutboundProtocol.TROJAN
    val isVless = selectedProtocol == OutboundProtocol.VLESS
    val isReality = security == "reality"
    val isTLS = security == "tls"

    val isValid = name.isNotEmpty() &&
            serverAddress.isNotEmpty() &&
            serverPort.toUShortOrNull() != null &&
            when {
                isNaive -> naiveUsername.isNotEmpty() && naivePassword.isNotEmpty()
                isShadowsocks -> ssPassword.isNotEmpty()
                isSocks5 -> true
                isTrojan -> trojanPassword.isNotEmpty()
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
            config.grpc?.let {
                grpcServiceName = it.serviceName
                grpcAuthority = it.authority
                grpcMultiMode = it.multiMode
                grpcUserAgent = it.userAgent
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
            trojanPassword = config.trojanPassword ?: ""
            config.trojanTls?.let {
                tlsSNI = it.serverName
                tlsALPN = it.alpn?.joinToString(",") ?: ""
                fingerprint = it.fingerprint
            }
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
                            !(isShadowsocks || isNaive || isSocks5 || isTrojan)
                        val parsedUUID = if (!needsUuid) {
                            configuration?.uuid ?: UUID.randomUUID()
                        } else {
                            runCatching { UUID.fromString(uuid) }.getOrNull() ?: return@IconButton
                        }

                        var tlsConfiguration: TlsConfiguration? = null
                        if (isTLS && isVless) {
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

                        // Trojan: TLS is mandatory. Build from the shared
                        // tlsSNI/tlsALPN/fingerprint state.
                        var trojanTlsConfiguration: TlsConfiguration? = null
                        if (isTrojan) {
                            val resolvedSni = tlsSNI.ifEmpty { serverAddress }
                            val alpn = tlsALPN.takeIf { it.isNotEmpty() }?.split(",")
                            trojanTlsConfiguration = TlsConfiguration(
                                serverName = resolvedSni,
                                alpn = alpn,
                                fingerprint = fingerprint
                            )
                            tlsConfiguration = trojanTlsConfiguration
                        }

                        var realityConfiguration: RealityConfiguration? = null
                        if (isReality && isVless) {
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
                        if (transport == "ws" && isVless) {
                            val host = wsHost.ifEmpty { serverAddress }
                            wsConfiguration = WebSocketConfiguration(host = host, path = wsPath)
                        }

                        var httpUpgradeConfiguration: HttpUpgradeConfiguration? = null
                        if (transport == "httpupgrade" && isVless) {
                            val host = httpUpgradeHost.ifEmpty { serverAddress }
                            httpUpgradeConfiguration = HttpUpgradeConfiguration(host = host, path = httpUpgradePath)
                        }

                        var xhttpConfiguration: XHttpConfiguration? = null
                        if (transport == "xhttp" && isVless) {
                            val host = xhttpHost.ifEmpty { serverAddress }
                            val mode = XHttpMode.fromRaw(xhttpMode)
                            xhttpConfiguration = XHttpConfiguration.fromExtraJson(
                                host = host, path = xhttpPath, mode = mode, extraJson = xhttpExtra
                            )
                        }

                        var grpcConfiguration: com.argsment.anywhere.vpn.protocol.grpc.GrpcConfiguration? = null
                        if (transport == "grpc" && isVless) {
                            grpcConfiguration = com.argsment.anywhere.vpn.protocol.grpc.GrpcConfiguration(
                                serviceName = grpcServiceName,
                                authority = grpcAuthority,
                                multiMode = grpcMultiMode,
                                userAgent = grpcUserAgent
                            )
                        }

                        val bareAddress = if (serverAddress.startsWith("[") && serverAddress.endsWith("]"))
                            serverAddress.drop(1).dropLast(1) else serverAddress

                        val naiveProto = when (selectedProtocol) {
                            OutboundProtocol.NAIVE_HTTP11 -> NaiveProtocol.HTTP11
                            OutboundProtocol.NAIVE_HTTP2 -> NaiveProtocol.HTTP2
                            else -> null
                        }

                        val nonVless = isShadowsocks || isNaive || isSocks5 || isTrojan

                        val config = ProxyConfiguration(
                            id = configuration?.id ?: UUID.randomUUID(),
                            name = name,
                            serverAddress = bareAddress,
                            serverPort = port,
                            uuid = parsedUUID,
                            encryption = if (nonVless) "none" else encryption,
                            transport = if (nonVless) "tcp" else transport,
                            flow = if (nonVless) null else flow.ifEmpty { null },
                            security = when {
                                isNaive || isShadowsocks || isSocks5 -> "none"
                                isTrojan -> "tls"
                                else -> security
                            },
                            tls = tlsConfiguration,
                            reality = realityConfiguration,
                            websocket = wsConfiguration,
                            httpUpgrade = httpUpgradeConfiguration,
                            xhttp = xhttpConfiguration,
                            grpc = grpcConfiguration,
                            muxEnabled = if (nonVless) false else muxEnabled,
                            xudpEnabled = if (nonVless) false else xudpEnabled,
                            subscriptionId = configuration?.subscriptionId,
                            outboundProtocol = selectedProtocol,
                            ssPassword = if (isShadowsocks) ssPassword else null,
                            ssMethod = if (isShadowsocks) ssMethod else null,
                            socks5Username = if (isSocks5) socks5Username.ifEmpty { null } else null,
                            socks5Password = if (isSocks5) socks5Password.ifEmpty { null } else null,
                            naiveUsername = if (isNaive) naiveUsername else null,
                            naivePassword = if (isNaive) naivePassword else null,
                            naiveProtocol = naiveProto,
                            trojanPassword = if (isTrojan) trojanPassword else null,
                            trojanTls = if (isTrojan) trojanTlsConfiguration else null,
                            // Preserve the original testseed rather than resetting to default.
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
            SectionHeader(stringResource(R.string.name))
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.name)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            SectionHeader(stringResource(R.string.protocol_label))
            DropdownField(
                label = stringResource(R.string.protocol_label),
                selectedValue = selectedProtocol.name,
                options = listOf(
                    OutboundProtocol.VLESS.name to "VLESS",
                    OutboundProtocol.TROJAN.name to "Trojan",
                    OutboundProtocol.SHADOWSOCKS.name to "Shadowsocks",
                    OutboundProtocol.SOCKS5.name to "SOCKS5",
                    OutboundProtocol.NAIVE_HTTP11.name to "HTTPS",
                    OutboundProtocol.NAIVE_HTTP2.name to "HTTP2"
                ),
                onSelect = { value ->
                    val nextProtocol = OutboundProtocol.valueOf(value)
                    selectedProtocol = nextProtocol
                    if (nextProtocol != OutboundProtocol.VLESS) {
                        flow = ""
                        transport = "tcp"
                        security = if (nextProtocol == OutboundProtocol.TROJAN) "tls" else "none"
                    }
                }
            )

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
            } else if (isTrojan) {
                // Trojan exposes only a password here; TLS SNI/ALPN/fingerprint
                // live in the shared TLS section below.
                OutlinedTextField(
                    value = trojanPassword,
                    onValueChange = { trojanPassword = it },
                    label = { Text(stringResource(R.string.password)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation()
                )
            } else {
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

            // Only VLESS exposes a user-selectable transport. Trojan mandates
            // TCP+TLS; Naive/SOCKS5/Shadowsocks have no transport knob.
            if (isVless) {
                SectionHeader(stringResource(R.string.transport))
                DropdownField(
                    label = stringResource(R.string.transport),
                    selectedValue = transport,
                    options = listOf(
                        "tcp" to "TCP",
                        "ws" to "WebSocket",
                        "httpupgrade" to "HTTPUpgrade",
                        "xhttp" to "XHTTP",
                        "grpc" to "gRPC"
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

                if (transport == "grpc") {
                    OutlinedTextField(
                        value = grpcServiceName,
                        onValueChange = { grpcServiceName = it },
                        label = { Text(stringResource(R.string.grpc_service_name)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = grpcAuthority,
                        onValueChange = { grpcAuthority = it },
                        label = { Text(stringResource(R.string.grpc_authority)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    DropdownField(
                        label = stringResource(R.string.mode),
                        selectedValue = if (grpcMultiMode) "multi" else "gun",
                        options = listOf(
                            "gun" to "Gun",
                            "multi" to "Multi"
                        ),
                        onSelect = { grpcMultiMode = (it == "multi") }
                    )
                    OutlinedTextField(
                        value = grpcUserAgent,
                        onValueChange = { grpcUserAgent = it },
                        label = { Text(stringResource(R.string.user_agent)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
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

            if (isVless || isTrojan) {
                SectionHeader("TLS")
                // For Trojan the TLS layer is mandatory: don't show the
                // none/TLS/Reality picker, just render the TLS fields directly.
                if (!isTrojan) {
                    DropdownField(
                        label = stringResource(R.string.security),
                        selectedValue = security,
                        options = listOf(
                            "none" to stringResource(R.string.none),
                            "tls" to "TLS",
                            "reality" to "Reality"
                        ),
                        onSelect = { security = it }
                    )
                }

                if (isTLS || isTrojan) {
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
                    if (!isTrojan) {
                        SwitchRow(
                            label = stringResource(R.string.allow_insecure),
                            checked = tlsAllowInsecure,
                            onCheckedChange = { tlsAllowInsecure = it }
                        )
                    }
                    FingerprintDropdown(
                        selected = fingerprint,
                        onSelect = { fingerprint = it }
                    )
                    if (!isTrojan) {
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
            TlsFingerprint.pickerFingerprints.forEach { fp ->
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
