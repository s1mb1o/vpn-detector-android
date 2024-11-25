package net.vpndetector.detect

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import java.net.NetworkInterface

/**
 * On-device VPN signals — passive checks using Android system APIs.
 * No network I/O.
 */
object SystemChecks {

    private val KNOWN_VPN_PACKAGES = listOf(
        "com.wireguard.android",
        "ch.protonvpn.android",
        "net.mullvad.mullvadvpn",
        "com.nordvpn.android",
        "com.expressvpn.vpn",
        "com.surfshark.vpnclient.android",
        "de.blinkt.openvpn",
        "net.openvpn.openvpn",
        "com.adguard.vpn",
        "app.intra",
        "org.proxydroid",
        "org.torproject.android",
        "com.guardianproject.netcipher",
        "com.sshtunnel.ssht",
    )

    private val KNOWN_PUBLIC_DNS = mapOf(
        "1.1.1.1" to "Cloudflare",
        "1.0.0.1" to "Cloudflare",
        "8.8.8.8" to "Google",
        "8.8.4.4" to "Google",
        "9.9.9.9" to "Quad9",
        "149.112.112.112" to "Quad9",
        "94.140.14.14" to "AdGuard",
        "94.140.15.15" to "AdGuard",
        "208.67.222.222" to "OpenDNS",
        "208.67.220.220" to "OpenDNS",
    )

    private val KNOWN_DOT_HOSTS = setOf(
        "dns.google", "1dot1dot1dot1.cloudflare-dns.com",
        "cloudflare-dns.com", "one.one.one.one",
        "dns.quad9.net", "dns.adguard.com", "dns.adguard-dns.com",
        "dns.nextdns.io", "dns11.quad9.net",
    )

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

        // 3. Tunnel interfaces
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

        // 6. HTTP proxy on active link
        run {
            val proxy = link?.httpProxy
            out += Check(
                id = "http_proxy",
                category = Category.SYSTEM,
                label = "HTTP proxy on link",
                value = proxy?.toString() ?: "none",
                severity = if (proxy != null) Severity.HARD else Severity.PASS,
                explanation = "LinkProperties.httpProxy. Any value = system-wide HTTP proxy, treated as VPN by SDKs.",
            )
        }

        // 7. Private DNS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val isActive = link?.isPrivateDnsActive == true
            val name = link?.privateDnsServerName
            val isKnownPublic = name != null && KNOWN_DOT_HOSTS.any { name.contains(it, ignoreCase = true) }
            val sev = when {
                isKnownPublic -> Severity.SOFT
                isActive -> Severity.SOFT
                else -> Severity.PASS
            }
            out += Check(
                id = "private_dns",
                category = Category.SYSTEM,
                label = "Private DNS (DoT)",
                value = when {
                    name != null -> "active: $name"
                    isActive -> "active (auto)"
                    else -> "off"
                },
                severity = sev,
                explanation = "Non-operator DoT (Cloudflare/Google/AdGuard) is an anti-fraud penalty signal.",
            )
        }

        // 8. DNS servers list
        run {
            val dns = link?.dnsServers?.map { it.hostAddress ?: it.toString() } ?: emptyList()
            val publicHits = dns.mapNotNull { KNOWN_PUBLIC_DNS[it]?.let { p -> "$it ($p)" } }
            out += Check(
                id = "dns_servers",
                category = Category.SYSTEM,
                label = "DNS servers",
                value = if (dns.isEmpty()) "none" else dns.joinToString(),
                severity = if (publicHits.isNotEmpty()) Severity.SOFT else Severity.PASS,
                explanation = "System DNS resolvers. Public providers (1.1.1.1, 8.8.8.8, AdGuard, Quad9) flag.",
            )
        }

        // 9. MTU of active interface
        run {
            val name = link?.interfaceName
            val mtu = name?.let {
                runCatching { NetworkInterface.getByName(it)?.mtu }.getOrNull()
            }
            val lowered = name?.lowercase()
            val sev = when {
                mtu == null || lowered == null -> Severity.INFO
                mtu in listOf(1280, 1380, 1420) -> Severity.SOFT
                mtu < 1500 && (lowered.startsWith("wlan") || lowered.startsWith("eth")) -> Severity.SOFT
                else -> Severity.PASS
            }
            out += Check(
                id = "mtu",
                category = Category.SYSTEM,
                label = "Active iface MTU",
                value = mtu?.toString() ?: "n/a",
                severity = sev,
                explanation = "Typical WG=1420, AmneziaWG≈1380, raw v4 MTU 1280. Non-1500 on Wi-Fi is suspicious.",
            )
        }

        // 10. Active transport type (context)
        run {
            val transport = when {
                caps == null -> "none"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WIFI"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "CELLULAR"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ETHERNET"
                else -> "OTHER"
            }
            out += Check(
                id = "active_transport",
                category = Category.SYSTEM,
                label = "Active transport",
                value = transport,
                severity = Severity.INFO,
                explanation = "Used by other checks to interpret consistency signals.",
            )
        }

        // 11. Installed VPN apps (SOFT — could be corp VPN, paid commercial)
        run {
            val pm = ctx.packageManager
            val installed = KNOWN_VPN_PACKAGES.filter { pkg ->
                runCatching {
                    pm.getPackageInfo(pkg, 0); true
                }.getOrDefault(false)
            }
            out += Check(
                id = "installed_vpn_apps",
                category = Category.SYSTEM,
                label = "Known VPN clients installed",
                value = if (installed.isEmpty()) "none" else installed.joinToString(),
                severity = if (installed.isNotEmpty()) Severity.SOFT else Severity.PASS,
                explanation = "PackageManager scan for known VPN client package names. " +
                    "SOFT because these have legitimate work / privacy uses.",
            )
        }

        // 12. Mock location enabled (best effort)
        run {
            val mock = runCatching {
                @Suppress("DEPRECATION")
                Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ALLOW_MOCK_LOCATION)
            }.getOrNull()
            val on = mock != null && mock != "0"
            out += Check(
                id = "mock_location",
                category = Category.SYSTEM,
                label = "Mock location",
                value = mock ?: "n/a",
                severity = if (on) Severity.SOFT else Severity.PASS,
                explanation = "Anti-fraud SDKs penalize mock-location-capable devices.",
            )
        }

        // 13. Developer options / ADB
        run {
            val dev = runCatching {
                Settings.Global.getInt(ctx.contentResolver,
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0)
            }.getOrDefault(0)
            val adb = runCatching {
                Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0)
            }.getOrDefault(0)
            out += Check(
                id = "dev_options",
                category = Category.SYSTEM,
                label = "Developer options / ADB",
                value = "dev=$dev adb=$adb",
                severity = Severity.INFO,
                explanation = "Diagnostic context. Often co-occurs with VPN setups but not a VPN signal itself.",
            )
        }

        // 14. Root indicators (cheap heuristic)
        run {
            val suExists = listOf(
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/su/bin/su", "/system/app/Superuser.apk", "/data/adb/magisk",
            ).any { java.io.File(it).exists() }
            val magiskPkg = runCatching {
                ctx.packageManager.getPackageInfo("com.topjohnwu.magisk", 0); true
            }.getOrDefault(false)
            val rooted = suExists || magiskPkg
            out += Check(
                id = "root",
                category = Category.SYSTEM,
                label = "Root indicators",
                value = if (rooted) "rooted (su=$suExists magisk=$magiskPkg)" else "stock",
                severity = if (rooted) Severity.SOFT else Severity.PASS,
                explanation = "Heuristic: su binary or Magisk presence. Combined with VPN amplifies suspicion.",
            )
        }

        // 15. Wi-Fi SSID (requires location permission on Android 10+)
        run {
            val hasFine = ContextCompat.checkSelfPermission(
                ctx, Manifest.permission.ACCESS_FINE_LOCATION
            ) == PackageManager.PERMISSION_GRANTED
            val wifi = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as? android.net.wifi.WifiManager
            @Suppress("DEPRECATION")
            val info = wifi?.connectionInfo
            val ssid = if (hasFine) info?.ssid else null
            out += Check(
                id = "wifi_ssid",
                category = Category.SYSTEM,
                label = "Wi-Fi SSID",
                value = ssid ?: "n/a (no permission or not on Wi-Fi)",
                severity = Severity.INFO,
                explanation = "Diagnostic — useful to tag runs by location.",
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
