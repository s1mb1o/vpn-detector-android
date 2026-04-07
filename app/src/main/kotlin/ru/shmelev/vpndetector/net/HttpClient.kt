package ru.shmelev.vpndetector.net

import okhttp3.OkHttpClient
import java.net.Proxy
import java.util.concurrent.TimeUnit

object Http {
    val client: OkHttpClient = OkHttpClient.Builder()
        // We deliberately use the system route — that *is* the measurement.
        // But disable any HTTP-level proxy auto-detection so we are not double-proxied.
        .proxy(Proxy.NO_PROXY)
        .connectTimeout(4, TimeUnit.SECONDS)
        .readTimeout(4, TimeUnit.SECONDS)
        .callTimeout(6, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .build()
}
