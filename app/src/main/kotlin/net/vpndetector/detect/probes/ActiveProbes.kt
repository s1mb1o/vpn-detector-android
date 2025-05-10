package net.vpndetector.detect.probes

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.Request
import net.vpndetector.detect.Category
import net.vpndetector.detect.Check
import net.vpndetector.detect.DetailEntry
import net.vpndetector.detect.Severity
import net.vpndetector.net.Http
import java.net.NetworkInterface

object ActiveProbes {

    // Global endpoints for baseline latency comparison.
    // Regional anchors can be added later for country-specific profiles.
    private val GLOBAL_ANCHORS = listOf(
        "https://www.google.com/favicon.ico",
        "https://www.cloudflare.com/favicon.ico",
        "https://www.apple.com/favicon.ico",
    )

    suspend fun run(): List<Check> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Check>()

        val results = coroutineScope {
            measureAll(GLOBAL_ANCHORS)
        }
        val median = median(results)

        out += Check(
            id = "lat_global",
            category = Category.PROBES,
            label = "Latency to global anchors (median)",
            value = if (median < 0) "n/a" else "$median ms",
            severity = when {
                median < 0 -> Severity.INFO
                median < 20 -> Severity.SOFT  // unusually fast = probably near a foreign exit
                else -> Severity.PASS
            },
            explanation = "Baseline latency to Google / Cloudflare / Apple. Unusually low latency " +
                "(<20ms) from a location far from these CDN PoPs may indicate VPN exit proximity.",
            details = results.map { it.toDetail() },
        )

        // IPv6 reachability
        val v6 = runCatching { fetch("https://api6.ipify.org") }.getOrNull()
        out += Check(
            id = "ipv6",
            category = Category.PROBES,
            label = "IPv6 external address",
            value = v6 ?: "no v6",
            severity = Severity.INFO,
            explanation = "Diagnostic. Split tunnels often leak v6 — compare with v4 country in GeoIP tab.",
        )

        // Local non-loopback addresses
        val locals = runCatching {
            NetworkInterface.getNetworkInterfaces().toList()
                .flatMap { ifc -> ifc.inetAddresses.toList().map { ifc.name to it.hostAddress } }
                .filter { (_, a) -> a != null && a != "127.0.0.1" && a != "::1" && !a.startsWith("fe80") }
                .joinToString { "${it.first}:${it.second}" }
        }.getOrDefault("")
        out += Check(
            id = "local_addrs",
            category = Category.PROBES,
            label = "Local addresses",
            value = locals.ifEmpty { "?" },
            severity = Severity.INFO,
            explanation = "All non-loopback link-local addresses on every interface.",
        )

        // Captive portal probe
        val cp = runCatching {
            val r = Http.client.newCall(Request.Builder()
                .url("http://connectivitycheck.gstatic.com/generate_204").build()).execute()
            r.use { it.code }
        }.getOrNull()
        out += Check(
            id = "captive_portal",
            category = Category.PROBES,
            label = "Captive portal probe (gstatic 204)",
            value = cp?.toString() ?: "fail",
            severity = if (cp == 204) Severity.PASS else Severity.SOFT,
            explanation = "Non-204 indicates a captive portal or middlebox interception.",
        )

        out
    }

    private fun fetch(url: String): String? = runCatching {
        Http.client.newCall(Request.Builder().url(url).build()).execute().use {
            if (!it.isSuccessful) return null
            it.body?.string()?.trim()
        }
    }.getOrNull()

    private data class HostLatency(
        val host: String,
        val url: String,
        val ms: Long,
        val error: String? = null,
    ) {
        fun toDetail(): DetailEntry = DetailEntry(
            source = host,
            reported = when {
                error != null -> "ERROR: $error"
                ms < 0 -> "no response"
                else -> "$ms ms"
            },
            verdict = when {
                error != null || ms < 0 -> Severity.INFO
                ms < 20 -> Severity.SOFT
                else -> Severity.PASS
            },
        )
    }

    private suspend fun measureAll(urls: List<String>): List<HostLatency> = coroutineScope {
        urls.map { url ->
            async {
                val host = runCatching { java.net.URI(url).host ?: url }.getOrDefault(url)
                try {
                    val start = System.nanoTime()
                    Http.client.newCall(Request.Builder().url(url).head().build()).execute().use { resp ->
                        if (!resp.isSuccessful && resp.code != 405) {
                            HostLatency(host, url, -1, error = "HTTP ${resp.code}")
                        } else {
                            HostLatency(host, url, (System.nanoTime() - start) / 1_000_000)
                        }
                    }
                } catch (e: Exception) {
                    HostLatency(host, url, -1, error = e.message ?: e.javaClass.simpleName)
                }
            }
        }.awaitAll()
    }

    private fun median(results: List<HostLatency>): Long {
        val ts = results.filter { it.error == null && it.ms >= 0 }.map { it.ms }.sorted()
        return if (ts.isEmpty()) -1 else ts[ts.size / 2]
    }
}
