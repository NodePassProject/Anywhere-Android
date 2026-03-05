# ============================================================================
# NativeBridge — JNI methods called from C and callback interface
# ============================================================================
-keep class com.argsment.anywhere.vpn.NativeBridge { *; }
-keep interface com.argsment.anywhere.vpn.NativeBridge$LwipCallback { *; }

# ============================================================================
# VPN Service + Binder (accessed via reflection by Android framework)
# ============================================================================
-keep class com.argsment.anywhere.vpn.AnywhereVpnService { *; }
-keep class com.argsment.anywhere.vpn.AnywhereVpnService$LocalBinder { *; }

# ============================================================================
# @Serializable data classes, enums, and custom serializers
# ============================================================================
-keep class com.argsment.anywhere.data.model.VlessConfiguration { *; }
-keep class com.argsment.anywhere.data.model.TlsConfiguration { *; }
-keep class com.argsment.anywhere.data.model.RealityConfiguration { *; }
-keep class com.argsment.anywhere.data.model.WebSocketConfiguration { *; }
-keep class com.argsment.anywhere.data.model.HttpUpgradeConfiguration { *; }
-keep class com.argsment.anywhere.data.model.XHttpConfiguration { *; }
-keep class com.argsment.anywhere.data.model.XHttpMode { *; }
-keep class com.argsment.anywhere.data.model.TlsFingerprint { *; }
-keep class com.argsment.anywhere.data.model.Subscription { *; }
-keep class com.argsment.anywhere.data.model.DomainRule { *; }
-keep class com.argsment.anywhere.data.model.DomainRuleType { *; }

# Custom serializers
-keep class com.argsment.anywhere.data.model.UuidSerializer { *; }
-keep class com.argsment.anywhere.data.model.Base64UrlByteArraySerializer { *; }
-keep class com.argsment.anywhere.data.model.HexByteArraySerializer { *; }

# Generated $$serializer companion classes
-keepclassmembers class com.argsment.anywhere.data.model.** {
    *** Companion;
}
-keepclasseswithmembers class com.argsment.anywhere.data.model.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# ============================================================================
# Compose Navigation route objects (serialized for type-safe nav)
# ============================================================================
-keep class com.argsment.anywhere.ui.navigation.HomeRoute { *; }
-keep class com.argsment.anywhere.ui.navigation.ProxiesRoute { *; }
-keep class com.argsment.anywhere.ui.navigation.SettingsRoute { *; }

# ============================================================================
# kotlinx.serialization infrastructure
# ============================================================================
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# ============================================================================
# Standard enum keepclassmembers
# ============================================================================
-keepclassmembers enum com.argsment.anywhere.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ============================================================================
# Crash reporting — preserve source file and line numbers
# ============================================================================
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
