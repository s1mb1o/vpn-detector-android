package net.vpndetector

import android.app.Application
import android.content.Context
import android.content.res.Resources
import androidx.annotation.StringRes

class VpnDetectorApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AppStrings.init(this)
    }
}

/**
 * Global access to the app's localized string resources, so non-Compose code
 * (the detect/ pipeline, share text, logcat) can resolve `@string/xxx` without
 * threading a Context through every function.
 */
object AppStrings {
    private lateinit var appContext: Context

    fun init(ctx: Context) {
        appContext = ctx.applicationContext
    }

    fun get(@StringRes id: Int): String = appContext.getString(id)
    fun get(@StringRes id: Int, vararg args: Any?): String = appContext.getString(id, *args)

    val resources: Resources get() = appContext.resources
}
