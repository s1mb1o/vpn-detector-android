package net.vpndetector.detect.probes

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import net.vpndetector.AppStrings
import net.vpndetector.R
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

        val unknownStatus = AppStrings.get(R.string.val_unknown)

        for (endpoint in ordered) {
            if (winnerIp != null) {
                details += DetailEntry(
                    source = endpoint.id,
                    reported = AppStrings.get(R.string.val_ref_skipped, winnerId ?: "", winnerIp ?: ""),
                    verdict = Severity.INFO,
                )
                continue
            }

            val response = runCatching { RawSocketHttp.get(endpoint.url) }.getOrElse { e ->
                details += DetailEntry(
                    source = endpoint.id,
                    reported = AppStrings.get(R.string.val_error_prefix, e.message ?: e.javaClass.simpleName),
                    verdict = Severity.INFO,
                )
                null
            } ?: continue

            val ip = extractIp(response.body)
            if (ip != null && ip != "127.0.0.1") {
                winnerId = endpoint.id
                winnerIp = ip
                val knownText = if (ip in knownIps) AppStrings.get(R.string.val_ref_seen)
                    else AppStrings.get(R.string.val_ref_not_seen)
                details += DetailEntry(
                    source = endpoint.id,
                    reported = AppStrings.get(
                        R.string.val_ref_winner_line,
                        ip,
                        response.statusCode?.toString() ?: unknownStatus,
                        knownText,
                    ),
                    verdict = if (ip in knownIps) Severity.PASS else Severity.SOFT,
                )
            } else {
                details += DetailEntry(
                    source = endpoint.id,
                    reported = if (ip == null) {
                        AppStrings.get(R.string.val_ref_no_ip_parsed, response.statusCode?.toString() ?: unknownStatus)
                    } else {
                        AppStrings.get(R.string.val_ref_loopback_rejected, ip)
                    },
                    verdict = Severity.INFO,
                )
            }
        }

        if (knownIps.isNotEmpty()) {
            details += DetailEntry(
                source = AppStrings.get(R.string.det_parallel_probes),
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
            label = AppStrings.get(R.string.check_ref_ip_first_success_label),
            value = when {
                winnerIp == null -> AppStrings.get(R.string.val_ref_no_ip)
                else -> AppStrings.get(R.string.val_ref_winner, winnerId ?: "", winnerIp ?: "")
            },
            severity = severity,
            explanation = AppStrings.get(R.string.check_ref_ip_first_success_explanation),
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
                    status.port != null -> AppStrings.get(R.string.val_ref_reachable, status.port, host.note)
                    else -> AppStrings.get(
                        R.string.val_ref_unreachable,
                        host.ports.joinToString(prefix = "[", postfix = "]"),
                        status.error ?: "error",
                    )
                },
                verdict = if (status.port != null) Severity.PASS else Severity.SOFT,
            )
        }

        Check(
            id = "ref_host_reachability",
            category = Category.PROBES,
            label = AppStrings.get(R.string.check_ref_host_reachability_label),
            value = when {
                missing.isEmpty() -> AppStrings.get(R.string.val_ref_hosts_reachable, reachable.size, REF_HOSTS.size)
                else -> AppStrings.get(
                    R.string.val_ref_hosts_reachable_with_missing,
                    reachable.size, REF_HOSTS.size, missing.joinToString(),
                )
            },
            severity = Severity.INFO,
            explanation = AppStrings.get(R.string.check_ref_host_reachability_explanation),
            details = details,
        )
    }

    private fun extractIp(body: String): String? =
        IPV6_REGEX.find(body)?.value ?: IPV4_REGEX.find(body)?.value
}
