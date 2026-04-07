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
