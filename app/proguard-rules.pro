# Diagnostic tool — minify on release to strip developer-machine paths from
# stack traces and shrink the APK. Keep rules below preserve runtime metadata
# that kotlinx.serialization, OkHttp, and Compose need.

# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keep,includedescriptorclasses class net.vpndetector.**$$serializer { *; }
-keepclassmembers class net.vpndetector.** {
    *** Companion;
}
-keepclasseswithmembers class net.vpndetector.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# OkHttp / Okio
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# Compose
-dontwarn androidx.compose.**

# Strip source-file attribute (also strips developer-path leaks)
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# Keep Log.i / Log.d in the release build — the QA harness logs every run
# under tag "VpnDetector" so testers can pull results via `adb logcat`.
# proguard-android-optimize.txt strips these by default; cancel that.
-keep class android.util.Log { *; }
-assumenosideeffects class android.util.Log {
    public static int v(...);
}
# (only verbose stripped; i/d/w/e preserved)
