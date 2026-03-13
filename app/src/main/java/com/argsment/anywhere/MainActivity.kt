package com.argsment.anywhere

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.argsment.anywhere.ui.navigation.AppNavigation
import com.argsment.anywhere.ui.onboarding.OnboardingScreen
import com.argsment.anywhere.ui.theme.AnywhereTheme
import com.argsment.anywhere.viewmodel.VpnViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: VpnViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            viewModel.onVpnPermissionGranted()
        } else {
            viewModel.onVpnPermissionDenied()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Wire VPN permission request
        viewModel.onRequestVpnPermission = { intent ->
            vpnPermissionLauncher.launch(intent)
        }

        setContent {
            AnywhereTheme {
                var onboardingCompleted by mutableStateOf(viewModel.hasCompletedOnboarding)

                if (!onboardingCompleted) {
                    OnboardingScreen(
                        onComplete = { bypassCountryCode, adBlockEnabled ->
                            viewModel.completeOnboarding(bypassCountryCode, adBlockEnabled)
                            onboardingCompleted = true
                        }
                    )
                } else {
                    AppNavigation(viewModel = viewModel)
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        viewModel.onRequestVpnPermission = null
    }
}
