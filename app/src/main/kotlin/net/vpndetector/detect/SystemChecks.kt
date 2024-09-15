package net.vpndetector.detect

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

/**
 * On-device VPN signals — passive checks using Android system APIs.
 * No network I/O, no special permissions beyond ACCESS_NETWORK_STATE.
 */
object SystemChecks {

    fun run(ctx: Context): List<Check> {
        val out = mutableListOf<Check>()
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val active = cm.activeNetwork
        val caps: NetworkCapabilities? = active?.let { cm.getNetworkCapabilities(it) }

        // TRANSPORT_VPN flag — the single most-checked anti-fraud signal.
        run {
            val isVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            out += Check(
                id = "transport_vpn",
                category = Category.SYSTEM,
                label = "TRANSPORT_VPN flag",
                value = isVpn.toString(),
                severity = if (isVpn) Severity.HARD else Severity.PASS,
                explanation = "ConnectivityManager.hasTransport(TRANSPORT_VPN). " +
                    "If true, a local VPN client is active. The most common anti-fraud signal.",
            )
        }

        return out
    }
}
