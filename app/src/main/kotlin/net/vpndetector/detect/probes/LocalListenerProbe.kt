package net.vpndetector.detect.probes

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import net.vpndetector.detect.Category
import net.vpndetector.detect.Check
import net.vpndetector.detect.DetailEntry
import net.vpndetector.detect.Severity
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Detects in-process / loopback proxy listeners.
 *
 * Modern Android does not let a regular app enumerate other apps' sockets via /proc/net/tcp
 * (SELinux). The reliable workaround is to TCP-connect to 127.0.0.1 on the well-known proxy
 * port set listed in the methodology §6.4 and treat any successful connect as proof that
 * something is listening on this device.
 *
 * Catches: Tor (Orbot 9050/9051), V2Ray local SOCKS (1080/1081), shadowsocks-android local
 * SOCKS, ByeDPI (8080), Outline / OutlineGo, AdGuard local proxy, Intra DNS proxy.
 *
 * Caveat: app's own network requests reach loopback through a separate FD pool, so probing
 * does NOT trigger the app to talk to itself even if the app exposes a debug listener.
 */
object LocalListenerProbe {

    /** Methodology §6.4 — characteristic proxy ports per technology. */
    private val PORT_LABELS: List<Pair<Int, String>> = listOf(
        // SOCKS
        1080 to "SOCKS",
        9000 to "SOCKS (alt)",
        5555 to "SOCKS (alt)",
        // Tor
        9050 to "Tor SOCKS",
        9051 to "Tor control",
        9150 to "Tor browser SOCKS",
        // HTTP
        3127 to "HTTP proxy",
        3128 to "HTTP proxy (Squid)",
        8000 to "HTTP proxy",
        8080 to "HTTP proxy",
        8081 to "HTTP proxy",
        8082 to "HTTP / transparent",
        8888 to "HTTP proxy",
        // Transparent / DPI bypass
        4080 to "transparent",
        7000 to "transparent",
        7044 to "transparent",
        12345 to "transparent",
        // Shadowsocks-android local SOCKS default
        1081 to "Shadowsocks local",
        // V2Ray local SOCKS / HTTP defaults
        1086 to "V2Ray local",
    )

    private const val CONNECT_TIMEOUT_MS = 60

    suspend fun run(): List<Check> = withContext(Dispatchers.IO) {
        val results: List<Triple<Int, String, Boolean>> = coroutineScope {
            PORT_LABELS.map { (port, label) ->
                async { Triple(port, label, probe(port)) }
            }.awaitAll()
        }
        val open = results.filter { it.third }
        val details = results.map { (port, label, isOpen) ->
            DetailEntry(
                source = "127.0.0.1:$port",
                reported = if (isOpen) "open · $label" else "closed",
                verdict = if (isOpen) Severity.SOFT else Severity.PASS,
            )
        }
        listOf(
            Check(
                id = "local_proxy_listeners",
                category = Category.PROBES,
                label = "Local proxy listeners",
                value = if (open.isEmpty()) "none open" else
                    open.joinToString { "${it.first}/${it.second}" },
                severity = if (open.isNotEmpty()) Severity.SOFT else Severity.PASS,
                explanation = "TCP-connects to 127.0.0.1 on the proxy ports listed in the methodology " +
                    "(SOCKS 1080/9000, Tor 9050/9051/9150, HTTP 3128/8080/8888, transparent 4080/7000/12345, " +
                    "Shadowsocks/V2Ray local 1081/1086, etc.). Any successful connect = a proxy is running " +
                    "on the device. SELinux blocks /proc/net/tcp enumeration, so this is the only fully " +
                    "reliable way for an unprivileged app to detect other-uid loopback listeners.",
                details = details,
            )
        )
    }

    private fun probe(port: Int): Boolean {
        val sock = Socket()
        return try {
            sock.connect(InetSocketAddress("127.0.0.1", port), CONNECT_TIMEOUT_MS)
            sock.isConnected
        } catch (e: Exception) {
            false
        } finally {
            try { sock.close() } catch (_: Exception) {}
        }
    }
}
