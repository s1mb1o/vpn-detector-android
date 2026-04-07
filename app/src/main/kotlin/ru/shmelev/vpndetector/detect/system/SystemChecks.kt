package ru.shmelev.vpndetector.detect.system

import android.Manifest
import android.app.ActivityManager
import android.app.AppOpsManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import android.provider.Settings
import androidx.core.content.ContextCompat
import ru.shmelev.vpndetector.detect.Category
import ru.shmelev.vpndetector.detect.Check
import ru.shmelev.vpndetector.detect.DetailEntry
import ru.shmelev.vpndetector.detect.Severity
import java.net.NetworkInterface

/**
 * On-device VPN signals — the catalog from the plan, Tab 1 (System).
 *
 * All checks are passive, no network I/O.
 */
object SystemChecks {

    private val KNOWN_VPN_PACKAGES = listOf(
        "org.amnezia.vpn",
        "com.wireguard.android",
        "org.outline.android.client",
        "ch.protonvpn.android",
        "net.mullvad.mullvadvpn",
        "com.nordvpn.android",
        "com.v2ray.ang",
        "com.github.shadowsocks",
        "com.expressvpn.vpn",
        "com.surfshark.vpnclient.android",
        "de.blinkt.openvpn",
        "net.openvpn.openvpn",
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

    /** Telegram-family packages. Telegram is a weak signal: presence + active use suggests
     *  the user routinely bypasses RKN's various Telegram blocks (router VPN, MTProto proxy, etc.). */
    private val TELEGRAM_PACKAGES = listOf(
        "org.telegram.messenger",          // official stable
        "org.telegram.messenger.web",      // official from web site
        "org.telegram.messenger.beta",     // beta
        "org.thunderdog.challegram",       // Telegram X
        "nekox.messenger",                 // NekoX fork
        "tw.nekomimi.nekogram",            // Nekogram
        "ua.itaysonlab.messenger",         // Forkgram
        "xyz.nextalone.nagram",            // Nagram
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
                    "If true any local VPN client is active. The single most-checked anti-fraud signal.",
            )
        }

        // 2. NET_CAPABILITY_NOT_VPN — only meaningful when there is an active network
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
                    explanation = "Mirror of TRANSPORT_VPN. SDKs check both to defeat naive bypasses.",
                )
            }
        }

        // 3. tun*/wg*/ppp*/utun*/tap* interfaces enumeration
        run {
            val all = try {
                NetworkInterface.getNetworkInterfaces().toList()
            } catch (e: Exception) {
                emptyList()
            }
            val flagged = all.filter { ifc ->
                val n = ifc.name.lowercase()
                (n.startsWith("tun") || n.startsWith("tap") ||
                    n.startsWith("wg") || n.startsWith("utun") || n.startsWith("ppp")) &&
                    runCatching { ifc.isUp }.getOrDefault(false)
            }
            out += Check(
                id = "tun_iface",
                category = Category.SYSTEM,
                label = "Tunnel interfaces present",
                value = if (flagged.isEmpty()) "none" else flagged.joinToString { it.name },
                severity = if (flagged.isNotEmpty()) Severity.HARD else Severity.PASS,
                explanation = "Any tun/tap/wg/utun/ppp interface that is UP indicates a local VPN.",
            )
        }

        // 4. Active iface name
        run {
            val name = link?.interfaceName ?: "?"
            val n = name.lowercase()
            val bad = n.startsWith("tun") || n.startsWith("tap") ||
                n.startsWith("wg") || n.startsWith("utun") || n.startsWith("ppp")
            out += Check(
                id = "active_iface_name",
                category = Category.SYSTEM,
                label = "Active interface name",
                value = name,
                severity = if (bad) Severity.HARD else Severity.PASS,
                explanation = "Active network's interface name. wlan*/rmnet*/ccmni* are normal; tun/wg are VPN.",
            )
        }

        // 5. Underlying networks — NetworkCapabilities.getUnderlyingNetworks() is @SystemApi
        // (hidden from regular apps), so we cannot call it without reflection.
        // Equivalent signal is already covered by transport_vpn + tun_iface.

        // 6. Default route via tun
        run {
            val routes = link?.routes.orEmpty()
            val defaultViaTun = routes.any { r ->
                val isDefault = r.isDefaultRoute || r.destination.toString().let { it == "0.0.0.0/0" || it == "::/0" }
                val ifc = (r.`interface` ?: link?.interfaceName ?: "").lowercase()
                isDefault && (ifc.startsWith("tun") || ifc.startsWith("wg") ||
                    ifc.startsWith("utun") || ifc.startsWith("ppp"))
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

        // 7. HTTP proxy on active link
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

        // 8. Private DNS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val active = link?.isPrivateDnsActive == true
            val name = link?.privateDnsServerName
            val isKnownPublic = name != null && KNOWN_DOT_HOSTS.any { name.contains(it, ignoreCase = true) }
            val sev = when {
                isKnownPublic -> Severity.SOFT
                active -> Severity.SOFT
                else -> Severity.PASS
            }
            out += Check(
                id = "private_dns",
                category = Category.SYSTEM,
                label = "Private DNS (DoT)",
                value = when {
                    name != null -> "active: $name"
                    active -> "active (auto)"
                    else -> "off"
                },
                severity = sev,
                explanation = "Non-operator DoT (Cloudflare/Google/AdGuard) is an anti-fraud penalty.",
            )
        }

        // 9. DNS servers list
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

        // 10. Always-on VPN
        run {
            val onApp = runCatching {
                Settings.Secure.getString(ctx.contentResolver, "always_on_vpn_app")
            }.getOrNull()
            val lockdown = runCatching {
                Settings.Secure.getInt(ctx.contentResolver, "always_on_vpn_lockdown", 0)
            }.getOrDefault(0)
            val on = !onApp.isNullOrEmpty()
            out += Check(
                id = "always_on_vpn",
                category = Category.SYSTEM,
                label = "Always-on VPN",
                value = if (on) "$onApp (lockdown=$lockdown)" else "off",
                severity = if (on) Severity.SOFT else Severity.PASS,
                explanation = "Settings.Secure always_on_vpn_app + always_on_vpn_lockdown.",
            )
        }

        // 11. Installed VPN apps
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
                explanation = "PackageManager scan for popular VPN client package names.",
            )
        }

        // 12. MTU of active iface
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

        // 13. Mock location enabled (best effort)
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
                explanation = "Banks penalize mock-location-capable devices.",
            )
        }

        // 14. Developer options / ADB
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

        // 15. Active transport type (context)
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
                explanation = "Used by other tabs to interpret consistency checks.",
            )
        }

        // 16. Root indicators (cheap heuristic)
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

        // 17. Wi-Fi SSID/BSSID context (requires location permission on Android 10+)
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
                explanation = "Diagnostic — useful to tag history entries by location.",
            )
        }

        // 18. Telegram presence (weak signal — see note in TELEGRAM_PACKAGES doc)
        run {
            val pm = ctx.packageManager
            val installed = TELEGRAM_PACKAGES.mapNotNull { pkg ->
                runCatching {
                    val pi = pm.getPackageInfo(pkg, 0)
                    pkg to pi
                }.getOrNull()
            }

            val hasUsageAccess = hasUsageStatsPermission(ctx)
            val running = if (hasUsageAccess) {
                runCatching { runningTelegramPids(ctx) }.getOrDefault(emptyList())
            } else emptyList()

            // Build per-source details
            val details = TELEGRAM_PACKAGES.map { pkg ->
                val pi = installed.firstOrNull { it.first == pkg }?.second
                val isRunning = pi != null && running.contains(pkg)
                val (reported, sev) = when {
                    pi == null -> "not installed" to Severity.PASS
                    isRunning -> "installed (vN/A) · running now" to Severity.SOFT
                    hasUsageAccess -> "installed · not in foreground" to Severity.SOFT
                    else -> "installed (running state unknown — grant Usage Access)" to Severity.SOFT
                }
                DetailEntry(source = pkg, reported = reported, verdict = sev)
            }

            val installedCount = installed.size
            val sev = if (installedCount > 0) Severity.SOFT else Severity.PASS
            out += Check(
                id = "telegram_present",
                category = Category.SYSTEM,
                label = "Telegram presence",
                value = when {
                    installedCount == 0 -> "none"
                    running.isNotEmpty() -> "$installedCount installed, ${running.size} running"
                    else -> "$installedCount installed"
                },
                severity = sev,
                explanation = "Weak signal: Telegram is recurrently throttled / blocked in RU. " +
                    "A user who keeps Telegram installed and uses it routinely is likely bypassing " +
                    "those restrictions (router VPN, MTProto proxy, etc.). Running-state detection " +
                    "needs Usage Access permission (Settings → Apps → Special access → Usage access).",
                details = details,
            )
        }

        return out
    }

    /** True iff the user has granted PACKAGE_USAGE_STATS to this app. */
    private fun hasUsageStatsPermission(ctx: Context): Boolean {
        val appOps = ctx.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                ctx.packageName,
            )
        } else {
            @Suppress("DEPRECATION")
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                ctx.packageName,
            )
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    /** Returns the subset of [TELEGRAM_PACKAGES] that has been used in the last 5 minutes
     *  (best-effort proxy for "running"). Requires Usage Access permission. */
    private fun runningTelegramPids(ctx: Context): List<String> {
        val usm = ctx.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            ?: return emptyList()
        val now = System.currentTimeMillis()
        val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, now - 24 * 3600_000L, now)
            ?: return emptyList()
        val recentMs = 5 * 60 * 1000L
        return stats.filter { it.packageName in TELEGRAM_PACKAGES && now - it.lastTimeUsed < recentMs }
            .map { it.packageName }
    }
}
