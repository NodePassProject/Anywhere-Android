package com.argsment.anywhere.ui.scanner

import android.Manifest
import com.argsment.anywhere.vpn.util.AnywhereLogger
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import com.argsment.anywhere.R
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors

@Composable
fun QrScannerScreen(
    onResult: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var hasCameraPermission by remember { mutableStateOf(false) }
    var permissionDenied by remember { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
        if (!granted) permissionDenied = true
    }

    LaunchedEffect(Unit) {
        val permission = Manifest.permission.CAMERA
        if (ContextCompat.checkSelfPermission(context, permission) == android.content.pm.PackageManager.PERMISSION_GRANTED) {
            hasCameraPermission = true
        } else {
            permissionLauncher.launch(permission)
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black)
        ) {
            when {
                hasCameraPermission -> {
                    CameraPreview(
                        onQrCodeDetected = { code ->
                            onResult(code)
                        }
                    )

                    // Scanning overlay
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Box(
                            modifier = Modifier
                                .size(250.dp)
                                .border(2.dp, Color.White.copy(alpha = 0.6f), RoundedCornerShape(16.dp))
                        )
                    }

                    // Title
                    Text(
                        text = stringResource(R.string.scan_your_qr_code),
                        color = Color.White,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier
                            .align(Alignment.TopCenter)
                            .padding(top = 64.dp)
                    )
                }

                permissionDenied -> {
                    Column(
                        modifier = Modifier.fillMaxSize(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = stringResource(R.string.permission_denied),
                            color = Color.White,
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(onClick = onDismiss) {
                            Text(stringResource(R.string.ok))
                        }
                    }
                }
            }

            // Close button
            IconButton(
                onClick = onDismiss,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(16.dp)
            ) {
                Icon(
                    Icons.Default.Close,
                    contentDescription = stringResource(R.string.cancel),
                    tint = Color.White
                )
            }
        }
    }
}

@Composable
@androidx.annotation.OptIn(androidx.camera.core.ExperimentalGetImage::class)
private fun CameraPreview(
    onQrCodeDetected: (String) -> Unit
) {
    val context = LocalContext.current
    // Use the hosting Activity's lifecycle (not the enclosing Dialog's
    // sub-lifecycle). Inside a Compose `Dialog`, `LocalLifecycleOwner`
    // resolves to a short-lived dialog-scoped owner whose state churns
    // during the CAMERA permission prompt (RESUMED → STARTED → CREATED
    // → STARTED → RESUMED). CameraX's `bindToLifecycle` can race that
    // transition and throw `IllegalArgumentException: Trying to create
    // use case with a LifecycleOwner that is in DESTROYED state`.
    // The Activity's lifecycle is stable for the duration of the scan.
    val lifecycleOwner = (context as? androidx.lifecycle.LifecycleOwner)
        ?: androidx.lifecycle.compose.LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    val hasDetected = remember { java.util.concurrent.atomic.AtomicBoolean(false) }
    val disposed = remember { java.util.concurrent.atomic.AtomicBoolean(false) }

    val previewView = remember { PreviewView(context) }
    // Narrow the scanner to QR codes only — cuts ML Kit model surface,
    // speeds up first-scan initialization, and avoids matching the
    // protocol QR against irrelevant formats like PDF417 or Aztec.
    val barcodeScanner = remember {
        val options = BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        BarcodeScanning.getClient(options)
    }
    val cameraProviderFutureRef = remember {
        androidx.compose.runtime.mutableStateOf<com.google.common.util.concurrent.ListenableFuture<ProcessCameraProvider>?>(null)
    }

    AndroidView(
        factory = { previewView },
        modifier = Modifier
            .fillMaxSize()
            .clip(RoundedCornerShape(0.dp))
    )

    DisposableEffect(Unit) {
        val logger = AnywhereLogger("QrScanner")
        val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
        cameraProviderFutureRef.value = cameraProviderFuture

        cameraProviderFuture.addListener({
            if (disposed.get()) return@addListener
            val cameraProvider = try {
                cameraProviderFuture.get()
            } catch (e: Exception) {
                logger.debug("Failed to obtain camera provider: ${e.message}")
                return@addListener
            }

            // Bail out if the dialog's lifecycle has already moved past STARTED — binding
            // to a DESTROYED LifecycleOwner throws IllegalArgumentException on CameraX.
            if (!lifecycleOwner.lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.CREATED)) {
                return@addListener
            }

            val preview = Preview.Builder().build().also {
                it.surfaceProvider = previewView.surfaceProvider
            }

            val resolutionSelector = ResolutionSelector.Builder()
                .setResolutionStrategy(
                    ResolutionStrategy(
                        Size(1280, 720),
                        ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER
                    )
                )
                .build()

            val imageAnalysis = ImageAnalysis.Builder()
                .setResolutionSelector(resolutionSelector)
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also { analysis ->
                    analysis.setAnalyzer(executor) analyzerLoop@ { imageProxy ->
                        if (disposed.get() || hasDetected.get()) {
                            imageProxy.close()
                            return@analyzerLoop
                        }
                        val mediaImage = imageProxy.image
                        if (mediaImage == null) {
                            imageProxy.close()
                            return@analyzerLoop
                        }
                        // Anything that throws between here and the
                        // `process()` call would leak the `ImageProxy`
                        // and stall CameraX (the pipeline waits for the
                        // frame to close). A hardware-specific rotation
                        // value or a malformed YUV plane can make
                        // `InputImage.fromMediaImage` throw; guard it.
                        val inputImage = try {
                            InputImage.fromMediaImage(
                                mediaImage,
                                imageProxy.imageInfo.rotationDegrees
                            )
                        } catch (e: Exception) {
                            logger.debug("InputImage.fromMediaImage failed: ${e.message}")
                            imageProxy.close()
                            return@analyzerLoop
                        }
                        val task = try {
                            barcodeScanner.process(inputImage)
                        } catch (e: Exception) {
                            // `process()` synchronously throws when the
                            // scanner has already been closed (dispose
                            // racing the analyzer thread).
                            logger.debug("Barcode process rejected: ${e.message}")
                            imageProxy.close()
                            return@analyzerLoop
                        }
                        task
                            .addOnSuccessListener { barcodes ->
                                if (disposed.get()) return@addOnSuccessListener
                                for (barcode in barcodes) {
                                    if (barcode.valueType == Barcode.TYPE_TEXT ||
                                        barcode.valueType == Barcode.TYPE_URL ||
                                        barcode.valueType == Barcode.TYPE_UNKNOWN) {
                                        val value = barcode.rawValue
                                        if (value != null && hasDetected.compareAndSet(false, true)) {
                                            onQrCodeDetected(value)
                                            break
                                        }
                                    }
                                }
                            }
                            .addOnFailureListener { e ->
                                logger.debug("Barcode scan failed: ${e.message}")
                            }
                            .addOnCompleteListener {
                                imageProxy.close()
                            }
                    }
                }

            try {
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    imageAnalysis
                )
            } catch (e: Exception) {
                logger.debug("Camera bind failed: ${e.message}")
            }
        }, ContextCompat.getMainExecutor(context))

        onDispose {
            disposed.set(true)
            try {
                val future = cameraProviderFutureRef.value
                if (future != null && future.isDone) {
                    future.get().unbindAll()
                }
            } catch (e: Exception) {
                AnywhereLogger("QrScanner").debug("onDispose unbind failed: ${e.message}")
            }
            try { barcodeScanner.close() } catch (_: Exception) {}
            try { executor.shutdown() } catch (_: Exception) {}
        }
    }
}
