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
import net.vpndetector.detect.geoip.ProbeResult
import net.vpndetector.net.RawSocketHttp
import java.util.Collections

/**
 * HOST_REACHABILITY parity diagnostics.
 *
 * Mirrors the anti-fraud telemetry pipeline documented in public RU research
 * on a reference messenger app (2026-04):
 * - six exact external-IP endpoints, shuffled, low-level socket transport,
 *   first-success wins;
 * - five exact HOST_REACHABILITY targets, recorded as booleans.
 *
 * These rows are intentionally diagnostic-first. They complement the broader
 * detector, but the existing GeoIP / Consistency / System checks remain the
 * authoritative scoring signals.
 */
object HostReachabilityProbes {

    private data class RefIpEndpoint(val id: String, val url: String)

    private data class RefHost(val host: String, val ports: List<Int>, val note: String)

    private val REF_IP_ENDPOINTS = listOf(
        RefIpEndpoint("yandex-v4", "https://ipv4-internet.yandex.net/api/v0/ip"),
        RefIpEndpoint("yandex-v6", "https://ipv6-internet.yandex.net/api/v0/ip"),
        RefIpEndpoint("ifconfig.me", "https://ifconfig.me/ip"),
        RefIpEndpoint("ipify", "https://api.ipify.org?format=json"),
        RefIpEndpoint("aws-checkip", "https://checkip.amazonaws.com/"),
        RefIpEndpoint("ip.mail.ru", "https://ip.mail.ru/"),
    )

    private val REF_HOSTS = listOf(
        RefHost("api.oneme.ru", listOf(443), "VK messenger API"),
        RefHost("gstatic.com", listOf(443), "Google connectivity"),
        RefHost("mtalk.google.com", listOf(5228, 5229, 5230), "Google push"),
        RefHost("calls.okcdn.ru", listOf(443), "VK calls CDN"),
        RefHost("gosuslugi.ru", listOf(443), "Gosuslugi"),
    )

    private val IPV4_REGEX = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b""")
    private val IPV6_REGEX = Regex("""(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}""")

    suspend fun run(probes: List<ProbeResult>): List<Check> = withContext(Dispatchers.IO) {
        coroutineScope {
            val ipDef = async { runRefIpCollector(probes) }
            val hostDef = async { runHostReachability() }
            listOf(ipDef.await(), hostDef.await())
        }
    }

    private fun runRefIpCollector(probes: List<ProbeResult>): Check {
        val ordered = REF_IP_ENDPOINTS.toMutableList()
        Collections.shuffle(ordered)

        val knownIps = probes.filter { it.error == null }.mapNotNull { it.ip }.toSet()
        val details = mutableListOf<DetailEntry>()
        var winnerId: String? = null
        var winnerIp: String? = null

        for (endpoint in ordered) {
            if (winnerIp != null) {
                details += DetailEntry(
                    source = endpoint.id,
                    reported = "skipped (winner already chosen: $winnerId -> $winnerIp)",
                    verdict = Severity.INFO,
                )
                continue
            }

            val response = runCatching { RawSocketHttp.get(endpoint.url) }.getOrElse { e ->
                details += DetailEntry(
                    source = endpoint.id,
                    reported = "ERROR: ${e.message ?: e.javaClass.simpleName}",
                    verdict = Severity.INFO,
                )
                null
            } ?: continue

            val ip = extractIp(response.body)
            if (ip != null && ip != "127.0.0.1") {
                winnerId = endpoint.id
                winnerIp = ip
                val known = if (ip in knownIps) "seen by parallel probes" else "not seen by parallel probes"
                details += DetailEntry(
                    source = endpoint.id,
                    reported = "$ip  (HTTP ${response.statusCode ?: "?"}; $known)",
                    verdict = if (ip in knownIps) Severity.PASS else Severity.SOFT,
                )
            } else {
                details += DetailEntry(
                    source = endpoint.id,
                    reported = if (ip == null) {
                        "no IP parsed (HTTP ${response.statusCode ?: "?"})"
                    } else {
                        "$ip rejected (loopback)"
                    },
                    verdict = Severity.INFO,
                )
            }
        }

        if (knownIps.isNotEmpty()) {
            details += DetailEntry(
                source = "parallel probes",
                reported = knownIps.joinToString(),
                verdict = Severity.INFO,
            )
        }

        val severity = when {
            winnerIp == null -> Severity.INFO
            winnerIp !in knownIps && knownIps.isNotEmpty() -> Severity.SOFT
            else -> Severity.INFO
        }

        return Check(
            id = "ref_ip_first_success",
            category = Category.PROBES,
            label = "Reference first-success IP collector",
            value = when {
                winnerIp == null -> "no usable IP returned"
                else -> "$winnerId -> $winnerIp"
            },
            severity = severity,
            explanation = "Mirrors the reference-messenger IP collector documented in public RU " +
                "anti-fraud research: the exact six endpoints are shuffled, queried over low-level " +
                "sockets, and the first endpoint returning a non-loopback IP wins. This row is " +
                "parity-focused; the full GeoIP tab remains the authoritative, richer view.",
            details = details,
        )
    }

    private suspend fun runHostReachability(): Check = coroutineScope {
        val results = REF_HOSTS.map { host ->
            async {
                host to RawSocketHttp.tcpReachable(host.host, host.ports)
            }
        }.awaitAll()

        val reachable = results.filter { (_, status) -> status.port != null }
        val missing = results.filter { (_, status) -> status.port == null }.map { it.first.host }
        val details = results.map { (host, status) ->
            DetailEntry(
                source = host.host,
                reported = when {
                    status.port != null -> "reachable on tcp/${status.port} (${host.note})"
                    else -> "unreachable via ${host.ports.joinToString(prefix = "[", postfix = "]")} · ${status.error ?: "error"}"
                },
                verdict = if (status.port != null) Severity.PASS else Severity.SOFT,
            )
        }

        Check(
            id = "ref_host_reachability",
            category = Category.PROBES,
            label = "HOST_REACHABILITY parity hosts",
            value = when {
                missing.isEmpty() -> "${reachable.size}/${REF_HOSTS.size} reachable"
                else -> "${reachable.size}/${REF_HOSTS.size} reachable · missing: ${missing.joinToString()}"
            },
            severity = Severity.INFO,
            explanation = "Mirrors the five-host reachability fingerprint documented in public RU " +
                "anti-fraud research: api.oneme.ru, gstatic.com, mtalk.google.com, calls.okcdn.ru, " +
                "gosuslugi.ru. The app records simple booleans here because the pattern is primarily " +
                "useful together with VPN flag, operator, and exit IP, not as a standalone verdict signal.",
            details = details,
        )
    }

    private fun extractIp(body: String): String? =
        IPV6_REGEX.find(body)?.value ?: IPV4_REGEX.find(body)?.value
}
