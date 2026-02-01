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

# Strip source-file attribute
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# Keep Log.i/d/w/e (strip verbose only)
-keep class android.util.Log { *; }
-assumenosideeffects class android.util.Log {
    public static int v(...);
}
