package net.vpndetector.detect.system

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
import net.vpndetector.AppStrings
import net.vpndetector.R
import net.vpndetector.detect.Category
import net.vpndetector.detect.Check
import net.vpndetector.detect.DetailEntry
import net.vpndetector.detect.Severity
import java.net.NetworkInterface

/**
 * On-device VPN signals — the catalog from the plan, Tab 1 (System).
 *
 * All checks are passive, no network I/O.
 */
object SystemChecks {

    private val KNOWN_VPN_PACKAGES = listOf(
        // Generic commercial VPN clients
        "com.wireguard.android",
        "ch.protonvpn.android",
        "net.mullvad.mullvadvpn",
        "com.nordvpn.android",
        "com.expressvpn.vpn",
        "com.surfshark.vpnclient.android",
        "de.blinkt.openvpn",
        "net.openvpn.openvpn",
        "com.adguard.vpn",
        // DPI / blocker bypass tools (less specific to state-level blocking)
        "app.intra",
        "org.proxydroid",
        "org.torproject.android",       // Orbot
        "com.guardianproject.netcipher",
        // Generic SOCKS / SSH tunnels
        "com.sshtunnel.ssht",
    )

    /**
     * Anti-censorship / anti-detection toolchain. These are not generic VPN clients — they are
     * **specifically designed** to defeat the same detection methodology this app implements
     * (AmneziaWG = WireGuard with junk-packet padding to bypass DPI fingerprinting; Xray /
     * VLESS-Reality = TLS-mimicking transport designed for RU; NekoBox / v2rayNG / Shadowsocks
     * = SOCKS-over-obfuscated-transport stacks; ByeDPI = TSPU bypass utility).
     *
     * Presence of any of these is a HARD signal: they have no legitimate "I just need a VPN
     * for work" use case the way ProtonVPN does. The user installed them for one reason.
     */
    private val ANTI_DETECTION_PACKAGES = listOf(
        // AmneziaWG (DPI-resistant WireGuard fork with junk-packet obfuscation)
        "org.amnezia.vpn",
        // Xray / VLESS / V2Ray ecosystem (Reality-transport, designed for anti-DPI)
        "com.v2ray.ang",                        // v2rayNG
        "com.xray.ang",
        "io.nekohasekai.sagernet",              // SagerNet
        "moe.matsuri.lite",                     // Matsuri
        "io.nekohasekai.sfa",                   // sing-box for Android
        "com.github.kr328.clash",               // Clash for Android
        "com.github.metacubex.clash.meta",      // Clash Meta / Mihomo
        "com.github.shadowsocks",               // shadowsocks-android
        "com.github.shadowsocksrr.android",     // ShadowsocksR
        "free.shadowsocks.proxy",
        // Outline (Shadowsocks-based, popular in RU bypass scene)
        "org.outline.android.client",
        "org.outline.go",
        // ByeDPI / GoodByeDPI Android forks (TSPU bypass)
        "io.github.romanvht.byedpi",
        "ru.gildor.coroutines.byedpi",
        "io.github.dovecoteescapee.byedpi",
        // NekoBox / NekoRay (Xray/sing-box GUI)
        "moe.nb4a",
        "com.nekohasekai.nekoray",
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
     *  the user routinely bypasses state-level Telegram blocks (router VPN, MTProto proxy, etc.). */
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
                label = AppStrings.get(R.string.check_transport_vpn_label),
                value = isVpn.toString(),
                severity = if (isVpn) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_transport_vpn_explanation),
            )
        }

        // 2. NET_CAPABILITY_NOT_VPN — only meaningful when there is an active network
        run {
            if (caps == null) {
                out += Check(
                    id = "cap_not_vpn",
                    category = Category.SYSTEM,
                    label = AppStrings.get(R.string.check_cap_not_vpn_label),
                    value = AppStrings.get(R.string.val_na_no_network),
                    severity = Severity.INFO,
                    explanation = AppStrings.get(R.string.check_cap_not_vpn_explanation_none),
                )
            } else {
                val notVpn = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                out += Check(
                    id = "cap_not_vpn",
                    category = Category.SYSTEM,
                    label = AppStrings.get(R.string.check_cap_not_vpn_label),
                    value = notVpn.toString(),
                    severity = if (!notVpn) Severity.HARD else Severity.PASS,
                    explanation = AppStrings.get(R.string.check_cap_not_vpn_explanation),
                )
            }
        }

        // 3. tun*/wg*/ppp*/utun*/tap*/ipsec* interfaces enumeration
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
                label = AppStrings.get(R.string.check_tun_iface_label),
                value = if (flagged.isEmpty()) AppStrings.get(R.string.val_none) else flagged.joinToString { it.name },
                severity = if (flagged.isNotEmpty()) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_tun_iface_explanation),
            )
        }

        // 4. Active iface name
        run {
            val name = link?.interfaceName ?: "?"
            val bad = isTunnelIfaceName(name)
            out += Check(
                id = "active_iface_name",
                category = Category.SYSTEM,
                label = AppStrings.get(R.string.check_active_iface_name_label),
                value = name,
                severity = if (bad) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_active_iface_name_explanation),
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
                label = AppStrings.get(R.string.check_default_route_tun_label),
                value = when {
                    defaultViaTun -> AppStrings.get(R.string.val_yes)
                    wgTrick -> AppStrings.get(R.string.val_wg_trick)
                    else -> AppStrings.get(R.string.val_no)
                },
                severity = sev,
                explanation = AppStrings.get(R.string.check_default_route_tun_explanation),
            )
        }

        // 7. HTTP proxy on active link
        run {
            val proxy = link?.httpProxy
            out += Check(
                id = "http_proxy",
                category = Category.SYSTEM,
                label = AppStrings.get(R.string.check_http_proxy_label),
                value = proxy?.toString() ?: AppStrings.get(R.string.val_none),
                severity = if (proxy != null) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_http_proxy_explanation),
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
                label = AppStrings.get(R.string.check_private_dns_label),
                value = when {
                    name != null -> AppStrings.get(R.string.val_private_dns_active_name, name)
                    active -> AppStrings.get(R.string.val_private_dns_active_auto)
                    else -> AppStrings.get(R.string.val_off)
                },
                severity = sev,
                explanation = AppStrings.get(R.string.check_private_dns_explanation),
            )
        }

        // 9. DNS servers list
        run {
            val dns = link?.dnsServers?.map { it.hostAddress ?: it.toString() } ?: emptyList()
            val publicHits = dns.mapNotNull { KNOWN_PUBLIC_DNS[it]?.let { p -> "$it ($p)" } }
            out += Check(
                id = "dns_servers",
                category = Category.SYSTEM,
                label = AppStrings.get(R.string.check_dns_servers_label),
                value = if (dns.isEmpty()) AppStrings.get(R.string.val_none) else dns.joinToString(),
                severity = if (publicHits.isNotEmpty()) Severity.SOFT else Severity.PASS,
                explanation = AppStrings.get(R.string.check_dns_servers_explanation),
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
                label = AppStrings.get(R.string.check_always_on_vpn_label),
                value = if (on) AppStrings.get(R.string.val_always_on_with_lockdown, onApp ?: "", lockdown)
                    else AppStrings.get(R.string.val_off),
                severity = if (on) Severity.SOFT else Severity.PASS,
                explanation = AppStrings.get(R.string.check_always_on_vpn_explanation),
            )
        }

        // 11. Installed generic VPN apps (SOFT — could be corp VPN, work VPN, paid commercial)
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
                label = AppStrings.get(R.string.check_installed_vpn_apps_label),
                value = if (installed.isEmpty()) AppStrings.get(R.string.val_none) else installed.joinToString(),
                severity = if (installed.isNotEmpty()) Severity.SOFT else Severity.PASS,
                explanation = AppStrings.get(R.string.check_installed_vpn_apps_explanation),
            )
        }

        // 11b. Anti-detection toolchain (HARD — purpose-built to defeat the methodology)
        run {
            val pm = ctx.packageManager
            val installed = ANTI_DETECTION_PACKAGES.filter { pkg ->
                runCatching {
                    pm.getPackageInfo(pkg, 0); true
                }.getOrDefault(false)
            }
            val details = installed.map { pkg ->
                val label = when {
                    pkg == "org.amnezia.vpn" -> AppStrings.get(R.string.val_aws_tag)
                    pkg.contains("v2ray") || pkg.contains("xray") -> AppStrings.get(R.string.val_tag_xray)
                    pkg.contains("sagernet") || pkg.contains("nekohasekai") || pkg.contains("matsuri") ||
                        pkg.contains("nb4a") || pkg.contains("nekoray") -> AppStrings.get(R.string.val_tag_sagernet)
                    pkg.contains("clash") || pkg.contains("mihomo") -> AppStrings.get(R.string.val_tag_clash)
                    pkg.contains("shadowsocks") -> AppStrings.get(R.string.val_tag_shadowsocks)
                    pkg.contains("outline") -> AppStrings.get(R.string.val_tag_outline)
                    pkg.contains("byedpi") -> AppStrings.get(R.string.val_tag_byedpi)
                    else -> AppStrings.get(R.string.val_tag_anti_detection)
                }
                DetailEntry(source = pkg, reported = label, verdict = Severity.HARD)
            }
            out += Check(
                id = "anti_detection_apps",
                category = Category.SYSTEM,
                label = AppStrings.get(R.string.check_anti_detection_apps_label),
                value = if (installed.isEmpty()) AppStrings.get(R.string.val_none)
                    else AppStrings.get(R.string.val_anti_detection_summary, installed.size, installed.joinToString()),
                severity = if (installed.isNotEmpty()) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_anti_detection_apps_explanation),
                details = details,
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
                label = AppStrings.get(R.string.check_mtu_label),
                value = mtu?.toString() ?: AppStrings.get(R.string.val_na),
                severity = sev,
                explanation = AppStrings.get(R.string.check_mtu_explanation),
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
                label = AppStrings.get(R.string.check_mock_location_label),
                value = mock ?: AppStrings.get(R.string.val_na),
                severity = if (on) Severity.SOFT else Severity.PASS,
                explanation = AppStrings.get(R.string.check_mock_location_explanation),
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
                label = AppStrings.get(R.string.check_dev_options_label),
                value = AppStrings.get(R.string.val_dev_options, dev, adb),
                severity = Severity.INFO,
                explanation = AppStrings.get(R.string.check_dev_options_explanation),
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
                label = AppStrings.get(R.string.check_active_transport_label),
                value = transport,
                severity = Severity.INFO,
                explanation = AppStrings.get(R.string.check_active_transport_explanation),
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
                label = AppStrings.get(R.string.check_root_label),
                value = if (rooted) AppStrings.get(R.string.val_rooted, suExists.toString(), magiskPkg.toString())
                    else AppStrings.get(R.string.val_stock),
                severity = if (rooted) Severity.SOFT else Severity.PASS,
                explanation = AppStrings.get(R.string.check_root_explanation),
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
                label = AppStrings.get(R.string.check_wifi_ssid_label),
                value = ssid ?: AppStrings.get(R.string.val_na_no_perm_or_wifi),
                severity = Severity.INFO,
                explanation = AppStrings.get(R.string.check_wifi_ssid_explanation),
            )
        }

        // 19. JVM-level system proxy properties (HTTP / HTTPS / SOCKS).
        // Methodology §6.4 mentions System.getProperty("http.proxyHost"). These are set
        // per-process or globally and survive even if LinkProperties.httpProxy is null.
        run {
            val keys = listOf(
                "http.proxyHost", "http.proxyPort",
                "https.proxyHost", "https.proxyPort",
                "socksProxyHost", "socksProxyPort",
            )
            val pairs = keys.mapNotNull { k ->
                val v = runCatching { System.getProperty(k) }.getOrNull()
                if (v.isNullOrBlank()) null else k to v
            }
            val anyHost = pairs.any { it.first.endsWith("Host") }
            out += Check(
                id = "jvm_proxy",
                category = Category.SYSTEM,
                label = AppStrings.get(R.string.check_jvm_proxy_label),
                value = if (pairs.isEmpty()) AppStrings.get(R.string.val_none)
                    else pairs.joinToString { "${it.first}=${it.second}" },
                severity = if (anyHost) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_jvm_proxy_explanation),
            )
        }

        // 20. VpnTransportInfo decoding (API 31+).
        // Methodology §6.4 explicitly mentions inspecting VpnTransportInfo for type, sessionId,
        // and bypassable. On API 31+ NetworkCapabilities exposes the per-VPN transport info.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val info = caps?.transportInfo
            val isVpnInfo = info != null && info.javaClass.simpleName == "VpnTransportInfo"
            val text = if (isVpnInfo) info.toString() else "(${AppStrings.get(R.string.val_none)})"
            out += Check(
                id = "vpn_transport_info",
                category = Category.SYSTEM,
                label = AppStrings.get(R.string.check_vpn_transport_info_label),
                value = text.take(200),
                severity = if (isVpnInfo) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_vpn_transport_info_explanation),
            )
        }

        // 21. Routing-table anomaly counts.
        // Methodology §7.6 lists multiple-default-route, dedicated routes via virtual interfaces,
        // and missing direct route to ISP gateway as indirect signals.
        run {
            val routes = link?.routes.orEmpty()
            val defaults = routes.filter { it.isDefaultRoute }
            val viaTunnel = routes.filter { r ->
                val ifc = r.`interface` ?: link?.interfaceName ?: ""
                isTunnelIfaceName(ifc)
            }
            val details = listOf(
                DetailEntry(AppStrings.get(R.string.det_default_routes), defaults.size.toString(),
                    if (defaults.size > 1) Severity.SOFT else Severity.PASS),
                DetailEntry(AppStrings.get(R.string.det_routes_via_tunnel), viaTunnel.size.toString(),
                    if (viaTunnel.isNotEmpty()) Severity.SOFT else Severity.PASS),
                DetailEntry(AppStrings.get(R.string.det_total_routes), routes.size.toString(), Severity.INFO),
            )
            val sev = if (defaults.size > 1 || viaTunnel.isNotEmpty()) Severity.SOFT else Severity.PASS
            out += Check(
                id = "route_anomalies",
                category = Category.SYSTEM,
                label = AppStrings.get(R.string.check_route_anomalies_label),
                value = AppStrings.get(R.string.val_default_routes_line, defaults.size, viaTunnel.size, routes.size),
                severity = sev,
                explanation = AppStrings.get(R.string.check_route_anomalies_explanation),
                details = details,
            )
        }

        // 22. dumpsys vpn_management — Android 12+ active VPN list.
        // Methodology §7.4 cites this. From a regular uid the system usually denies the call,
        // but on some OEM ROMs and userdebug builds it returns useful output. Best-effort.
        run {
            val (output, ok) = runDumpsys()
            val pkgRegex = Regex("""(?:Active package name|Active vpn package):\s*(\S+)""")
            val pkgs = pkgRegex.findAll(output).map { it.groupValues[1] }.toList().distinct()
            val sev = when {
                !ok -> Severity.INFO
                pkgs.isNotEmpty() -> Severity.HARD
                else -> Severity.PASS
            }
            out += Check(
                id = "dumpsys_vpn",
                category = Category.SYSTEM,
                label = AppStrings.get(R.string.check_dumpsys_vpn_label),
                value = when {
                    !ok -> AppStrings.get(R.string.val_dumpsys_denied)
                    pkgs.isEmpty() -> AppStrings.get(R.string.val_no_active_vpn)
                    else -> pkgs.joinToString()
                },
                severity = sev,
                explanation = AppStrings.get(R.string.check_dumpsys_vpn_explanation),
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
                    pi == null -> AppStrings.get(R.string.val_telegram_not_installed) to Severity.PASS
                    isRunning -> AppStrings.get(R.string.val_telegram_running) to Severity.SOFT
                    hasUsageAccess -> AppStrings.get(R.string.val_telegram_not_foreground) to Severity.SOFT
                    else -> AppStrings.get(R.string.val_telegram_running_unknown) to Severity.SOFT
                }
                DetailEntry(source = pkg, reported = reported, verdict = sev)
            }

            val installedCount = installed.size
            val sev = if (installedCount > 0) Severity.SOFT else Severity.PASS
            out += Check(
                id = "telegram_present",
                category = Category.SYSTEM,
                label = AppStrings.get(R.string.check_telegram_present_label),
                value = when {
                    installedCount == 0 -> AppStrings.get(R.string.val_none)
                    running.isNotEmpty() ->
                        AppStrings.get(R.string.val_telegram_installed_running, installedCount, running.size)
                    else -> AppStrings.get(R.string.val_telegram_installed_count, installedCount)
                },
                severity = sev,
                explanation = AppStrings.get(R.string.check_telegram_present_explanation),
                details = details,
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

    /** Best-effort `dumpsys vpn_management` shell-out. Returns (combined output, succeeded). */
    private fun runDumpsys(): Pair<String, Boolean> = try {
        val pb = ProcessBuilder("/system/bin/dumpsys", "vpn_management").redirectErrorStream(true)
        val p = pb.start()
        val finished = p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)
        if (!finished) {
            p.destroyForcibly()
            "" to false
        } else {
            val out = p.inputStream.bufferedReader().use { it.readText() }
            // dumpsys returns 0 even on permission denial; treat empty/short output as denied.
            val ok = out.length > 50 && !out.contains("Permission Denial", ignoreCase = true)
            out to ok
        }
    } catch (e: Exception) {
        "" to false
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
