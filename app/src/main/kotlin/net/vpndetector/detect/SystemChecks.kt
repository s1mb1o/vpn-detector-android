package net.vpndetector.detect

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import java.net.NetworkInterface

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
        val link: LinkProperties? = active?.let { cm.getLinkProperties(it) }

        // 1. TRANSPORT_VPN flag
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

        // 2. NET_CAPABILITY_NOT_VPN
        run {
            if (caps == null) {
                out += Check(
                    id = "cap_not_vpn",
                    category = Category.SYSTEM,
                    label = "NET_CAPABILITY_NOT_VPN",
                    value = "n/a (no active network)",
                    severity = Severity.INFO,
                    explanation = "Cannot evaluate while offline / between network handoffs.",
                )
            } else {
                val notVpn = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                out += Check(
                    id = "cap_not_vpn",
                    category = Category.SYSTEM,
                    label = "NET_CAPABILITY_NOT_VPN",
                    value = notVpn.toString(),
                    severity = if (!notVpn) Severity.HARD else Severity.PASS,
                    explanation = "Mirror of TRANSPORT_VPN. Anti-fraud SDKs check both to defeat naive bypasses.",
                )
            }
        }

        // 3. Tunnel interfaces (tun/tap/wg/utun/ppp/ipsec)
        run {
            val all = try {
                NetworkInterface.getNetworkInterfaces().toList()
            } catch (e: Exception) {
                emptyList()
            }
            val flagged = all.filter { ifc ->
                isTunnelIfaceName(ifc.name) &&
                    runCatching { ifc.isUp }.getOrDefault(false)
            }
            out += Check(
                id = "tun_iface",
                category = Category.SYSTEM,
                label = "Tunnel interfaces present",
                value = if (flagged.isEmpty()) "none" else flagged.joinToString { it.name },
                severity = if (flagged.isNotEmpty()) Severity.HARD else Severity.PASS,
                explanation = "Any tun/tap/wg/utun/ppp/ipsec interface that is UP indicates a local VPN " +
                    "or IPsec/IKEv2 tunnel client.",
            )
        }

        // 4. Active interface name
        run {
            val name = link?.interfaceName ?: "?"
            val bad = isTunnelIfaceName(name)
            out += Check(
                id = "active_iface_name",
                category = Category.SYSTEM,
                label = "Active interface name",
                value = name,
                severity = if (bad) Severity.HARD else Severity.PASS,
                explanation = "Active network's interface name. wlan*/rmnet*/ccmni* are normal; " +
                    "tun/wg/utun/ppp/ipsec indicate VPN.",
            )
        }

        // 5. Default route via tunnel
        run {
            val routes = link?.routes.orEmpty()
            val defaultViaTun = routes.any { r ->
                val isDefault = r.isDefaultRoute || r.destination.toString().let { it == "0.0.0.0/0" || it == "::/0" }
                val ifc = r.`interface` ?: link?.interfaceName ?: ""
                isDefault && isTunnelIfaceName(ifc)
            }
            // Detect WG split-route trick (0.0.0.0/1 + 128.0.0.0/1)
            val wgTrick = routes.any { it.destination.toString() == "0.0.0.0/1" } &&
                routes.any { it.destination.toString() == "128.0.0.0/1" }
            val sev = when {
                defaultViaTun -> Severity.HARD
                wgTrick -> Severity.HARD
                else -> Severity.PASS
            }
            out += Check(
                id = "default_route_tun",
                category = Category.SYSTEM,
                label = "Default route via tunnel",
                value = if (defaultViaTun) "yes" else if (wgTrick) "WG split-route trick" else "no",
                severity = sev,
                explanation = "0.0.0.0/0 via tun OR the 0.0.0.0/1 + 128.0.0.0/1 trick (WireGuard signature).",
            )
        }

        return out
    }

    /** Tunnel-interface name match used everywhere we look at iface names. */
    private fun isTunnelIfaceName(name: String): Boolean {
        val n = name.lowercase()
        return n.startsWith("tun") || n.startsWith("tap") || n.startsWith("wg") ||
            n.startsWith("utun") || n.startsWith("ppp") || n.startsWith("ipsec")
    }
}
