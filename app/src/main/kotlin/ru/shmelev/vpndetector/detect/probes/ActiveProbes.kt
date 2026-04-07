package ru.shmelev.vpndetector.detect.probes

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.Request
import ru.shmelev.vpndetector.detect.Category
import ru.shmelev.vpndetector.detect.Check
import ru.shmelev.vpndetector.detect.Severity
import ru.shmelev.vpndetector.net.Http
import java.net.NetworkInterface

object ActiveProbes {

    private val RU_ANCHORS = listOf(
        "https://yandex.ru/favicon.ico",
        "https://mail.ru/favicon.ico",
        "https://vk.com/favicon.ico",
    )
    private val FOREIGN_ANCHORS = listOf(
        "https://www.google.com/favicon.ico",
        "https://www.cloudflare.com/favicon.ico",
        "https://www.wikipedia.org/favicon.ico",
    )

    suspend fun run(): List<Check> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Check>()

        val (ru, foreign) = coroutineScope {
            val a = async { medianLatencyParallel(RU_ANCHORS) }
            val b = async { medianLatencyParallel(FOREIGN_ANCHORS) }
            a.await() to b.await()
        }

        out += Check(
            id = "lat_ru",
            category = Category.PROBES,
            label = "Latency to RU anchors (median)",
            value = "${ru} ms",
            severity = when {
                ru < 0 -> Severity.INFO
                ru > 200 -> Severity.HARD
                ru > 100 -> Severity.SOFT
                else -> Severity.PASS
            },
            explanation = "yandex.ru / mail.ru / vk.com. >200ms suggests transit through a foreign exit and back.",
        )

        out += Check(
            id = "lat_foreign",
            category = Category.PROBES,
            label = "Latency to foreign anchors (median)",
            value = "${foreign} ms",
            severity = when {
                foreign < 0 -> Severity.INFO
                foreign < 30 -> Severity.HARD
                foreign < 80 -> Severity.SOFT
                else -> Severity.PASS
            },
            explanation = "google / cloudflare / wikipedia. <30ms from a RU device = foreign exit (VPN).",
        )

        out += Check(
            id = "lat_ratio",
            category = Category.PROBES,
            label = "RU vs foreign latency ordering",
            value = if (ru < 0 || foreign < 0) "n/a" else if (ru < foreign) "RU faster ✓" else "foreign faster ✗",
            severity = when {
                ru < 0 || foreign < 0 -> Severity.INFO
                ru < foreign -> Severity.PASS
                else -> Severity.HARD
            },
            explanation = "From a real RU connection RU anchors must be faster than foreign anchors.",
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

    /** Median TTFB across [urls], in milliseconds. -1 on total failure. Probes run in parallel. */
    private suspend fun medianLatencyParallel(urls: List<String>): Long = coroutineScope {
        val ts = urls.map { url ->
            async {
                runCatching {
                    val start = System.nanoTime()
                    Http.client.newCall(Request.Builder().url(url).head().build()).execute().use {
                        if (!it.isSuccessful && it.code != 405) return@runCatching null
                        (System.nanoTime() - start) / 1_000_000
                    }
                }.getOrNull()
            }
        }.awaitAll().filterNotNull().sorted()
        if (ts.isEmpty()) -1 else ts[ts.size / 2]
    }
}
