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

    // Anchors must respond to HEAD with 2xx (or 405 which we accept).
    // Avoid hosts with anti-bot tarpits (vk.com → 418) and HEAD blockers (wikipedia.org → 403).
    private val RU_ANCHORS = listOf(
        "https://yandex.ru/favicon.ico",
        "https://mail.ru/favicon.ico",
        "https://gosuslugi.ru/favicon.ico",
    )
    private val FOREIGN_ANCHORS = listOf(
        "https://www.google.com/favicon.ico",
        "https://www.cloudflare.com/favicon.ico",
        "https://www.apple.com/favicon.ico",
    )

    suspend fun run(): List<Check> = withContext(Dispatchers.IO) {
        val out = mutableListOf<Check>()

        val (ruResults, foreignResults) = coroutineScope {
            val a = async { measureAll(RU_ANCHORS) }
            val b = async { measureAll(FOREIGN_ANCHORS) }
            a.await() to b.await()
        }
        val ru = median(ruResults)
        val foreign = median(foreignResults)

        // Latency checks are methodology §10.1 "дополнительные методы" — supplementary.
        // They corroborate other signals, they do not stand alone. On mobile cellular
        // the absolute numbers are noisy (bad RSRP, handoffs, carrier transit variance)
        // and foreign CDNs can legitimately be closer than RU origin servers, so we cap
        // these checks at SOFT and loosen the "slow RU" threshold.
        out += Check(
            id = "lat_ru",
            category = Category.PROBES,
            label = "Latency to RU anchors (median)",
            value = if (ru < 0) "n/a" else "$ru ms",
            severity = when {
                ru < 0 -> Severity.INFO
                ru > 400 -> Severity.SOFT      // was 200=HARD; cellular can easily hit 200
                else -> Severity.PASS
            },
            explanation = "yandex.ru / mail.ru / gosuslugi.ru. Supplementary signal (methodology §10.1). " +
                "Cellular networks have high baseline latency, so this is capped at SOFT and only fires " +
                "above 400ms. Tap to see per-host latency.",
            details = ruResults.map { it.toDetail(slowMs = 400, warnMs = 200) },
        )

        out += Check(
            id = "lat_foreign",
            category = Category.PROBES,
            label = "Latency to foreign anchors (median)",
            value = if (foreign < 0) "n/a" else "$foreign ms",
            severity = when {
                foreign < 0 -> Severity.INFO
                foreign < 20 -> Severity.SOFT  // was <30=HARD; modern CDNs + operator peering often hit 25-30ms
                else -> Severity.PASS
            },
            explanation = "google / cloudflare / apple. Supplementary signal (methodology §10.1). " +
                "Modern CDNs have PoPs close to RU mobile operators, so foreign latency alone is weak. " +
                "Capped at SOFT and only fires below 20ms. Tap to see per-host latency.",
            details = foreignResults.map { it.toForeignDetail(fastMs = 20, warnMs = 50) },
        )

        out += Check(
            id = "lat_ratio",
            category = Category.PROBES,
            label = "RU vs foreign latency ordering",
            value = if (ru < 0 || foreign < 0) "n/a"
                else if (ru < foreign) "RU faster ✓ ($ru < $foreign ms)"
                else "foreign faster ($foreign < $ru ms)",
            severity = when {
                ru < 0 || foreign < 0 -> Severity.INFO
                ru < foreign -> Severity.PASS
                // Ordering is only a weak signal — RU origin servers often sit in RU datacenters
                // that are further (latency-wise) than the closest Google/Cloudflare PoP. Mark INFO,
                // not a scoring contributor, because the methodology §10.1 treats SNITCH as
                // supplementary ('дополнительные методы') that corroborates GeoIP rather than
                // standing alone.
                else -> Severity.INFO
            },
            explanation = "From a real RU connection RU anchors are often faster than foreign, but modern " +
                "CDNs (Google, Cloudflare) frequently have PoPs closer to the operator's core than the " +
                "RU origin servers themselves. Reversed ordering alone does not indicate VPN; downgraded to " +
                "INFO. Tap to see per-host measurements.",
            details = (ruResults.map { it.copy(group = "RU") } + foreignResults.map { it.copy(group = "foreign") })
                .map { DetailEntry(source = "[${it.group}] ${it.host}", reported = it.reportedString(), verdict = Severity.INFO) },
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

    /** One latency measurement for a single URL. */
    private data class HostLatency(
        val host: String,
        val url: String,
        val ms: Long,           // -1 on failure
        val error: String? = null,
        val group: String = "",
    ) {
        fun reportedString(): String = when {
            error != null -> "ERROR: $error"
            ms < 0 -> "no response"
            else -> "$ms ms"
        }

        /** Severity for an RU anchor: slow = bad. */
        fun toDetail(slowMs: Long, warnMs: Long): DetailEntry = DetailEntry(
            source = host,
            reported = reportedString(),
            verdict = when {
                error != null || ms < 0 -> Severity.INFO
                ms > slowMs -> Severity.HARD
                ms > warnMs -> Severity.SOFT
                else -> Severity.PASS
            },
        )

        /** Severity for a foreign anchor: too-fast = bad (= foreign exit). */
        fun toForeignDetail(fastMs: Long, warnMs: Long): DetailEntry = DetailEntry(
            source = host,
            reported = reportedString(),
            verdict = when {
                error != null || ms < 0 -> Severity.INFO
                ms < fastMs -> Severity.HARD
                ms < warnMs -> Severity.SOFT
                else -> Severity.PASS
            },
        )
    }

    /** Probe every URL in parallel; return one HostLatency per URL. */
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
