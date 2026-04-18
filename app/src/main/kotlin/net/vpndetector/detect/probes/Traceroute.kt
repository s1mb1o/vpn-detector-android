package net.vpndetector.detect.probes

import android.content.Context
import android.telephony.TelephonyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import okhttp3.Request
import net.vpndetector.AppStrings
import net.vpndetector.R
import net.vpndetector.detect.Category
import net.vpndetector.detect.Check
import net.vpndetector.detect.DetailEntry
import net.vpndetector.detect.Severity
import net.vpndetector.net.AppJson
import net.vpndetector.net.Http
import java.util.concurrent.TimeUnit

/**
 * Check C — Router egress traceroute.
 *
 * Uses the on-device `/system/bin/ping` binary with `-t TTL` to map the L3 path
 * to several fixed anchors in parallel. Path A from `docs/specs/04_proposed-checks.md`:
 * unprivileged ICMP socket, no root, no permissions beyond INTERNET.
 *
 * Multi-target: a single foreign anchor only reveals "some traffic goes abroad".
 * Probing both foreign (1.1.1.1, 8.8.8.8) and RU-anchored (77.88.8.8) hosts
 * surfaces split-routing policies — e.g. whitelist-routing routers that keep
 * RU destinations local but tunnel foreign traffic out, which would trip the
 * foreign targets' verdicts while the RU target stays clean.
 *
 * Verdict rule (per target): if the first non-RFC1918 hop's country differs
 * from the SIM country, that target egresses through a router-side VPN.
 * Aggregate verdict: worst across targets — HARD if any target differs.
 */
object Traceroute {

    private const val MAX_TTL = 15
    private const val PING_TIMEOUT_S = 2L
    private val HOP_REGEX = Regex("""(?:From\s+|bytes from\s+)(\d{1,3}(?:\.\d{1,3}){3})""")

    private data class Target(val ip: String, val name: String)

    private val TARGETS = listOf(
        Target("1.1.1.1", "Cloudflare"),
        Target("8.8.8.8", "Google DNS"),
        Target("77.88.8.8", "Yandex DNS"),
    )

    @Serializable
    private data class IpinfoLite(
        val ip: String? = null,
        val country: String? = null,
        val city: String? = null,
        val org: String? = null,
    )

    private data class Hop(val ttl: Int, val ip: String?, val isFinal: Boolean)
    private data class TargetTrace(val target: Target, val hops: List<Hop>)
    private data class Per(
        val target: Target,
        val firstPublic: Hop?,
        val country: String?,
        val verdict: Severity,
    )

    suspend fun run(ctx: Context): List<Check> = withContext(Dispatchers.IO) {
        val traces = coroutineScope {
            TARGETS.map { t -> async { TargetTrace(t, traceroute(t.ip)) } }.awaitAll()
        }

        if (traces.all { tr -> tr.hops.all { it.ip == null } }) {
            return@withContext listOf(
                Check(
                    id = "router_egress_country",
                    category = Category.PROBES,
                    label = AppStrings.get(R.string.check_router_egress_country_label),
                    value = AppStrings.get(R.string.val_no_hops_returned),
                    severity = Severity.INFO,
                    explanation = AppStrings.get(R.string.check_router_egress_country_no_hops),
                )
            )
        }

        // Trim each trace at first final reply (don't show ghosts past the destination)
        val trimmed = traces.map { tr ->
            val finalIdx = tr.hops.indexOfFirst { it.isFinal }
            TargetTrace(tr.target, if (finalIdx >= 0) tr.hops.take(finalIdx + 1) else tr.hops)
        }

        // Dedupe ipinfo lookups across all targets
        val allPublicIps = trimmed.flatMap { it.hops.mapNotNull { h -> h.ip } }
            .filter { !isPrivate(it) }.distinct()
        val ipinfo = allPublicIps.associateWith { lookupIpinfo(it) }

        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        val simCountry = (tm?.simCountryIso?.takeIf { it.isNotEmpty() }
            ?: tm?.networkCountryIso.orEmpty()).uppercase()

        val per = trimmed.map { tr ->
            val first = tr.hops.firstOrNull { it.ip != null && !isPrivate(it.ip) }
            val country = first?.ip?.let { ipinfo[it]?.country?.uppercase() }
            val v: Severity = when {
                first == null -> Severity.INFO
                simCountry.isEmpty() || country == null -> Severity.INFO
                country == simCountry -> Severity.PASS
                else -> Severity.HARD
            }
            Per(tr.target, first, country, v)
        }

        val aggregate = when {
            per.any { it.verdict == Severity.HARD } -> Severity.HARD
            per.any { it.verdict == Severity.PASS } && per.none { it.verdict == Severity.HARD } -> Severity.PASS
            else -> Severity.INFO
        }

        val unknown = AppStrings.get(R.string.val_unknown)
        val details = trimmed.flatMap { tr ->
            val p = per.first { it.target == tr.target }
            tr.hops.map { h ->
                val info = h.ip?.let { ipinfo[it] }
                val reported = when {
                    h.ip == null -> AppStrings.get(R.string.val_no_reply)
                    isPrivate(h.ip) -> AppStrings.get(R.string.val_private, h.ip)
                    info == null -> AppStrings.get(R.string.val_geoip_lookup_failed, h.ip)
                    else -> AppStrings.get(
                        R.string.val_hop_with_info,
                        h.ip, info.country ?: unknown, info.city.orEmpty(), info.org.orEmpty(),
                    ).trim()
                }
                val sev = when {
                    h.ip == null -> Severity.INFO
                    isPrivate(h.ip) -> Severity.INFO
                    info?.country == null -> Severity.INFO
                    h == p.firstPublic && p.verdict == Severity.HARD -> Severity.HARD
                    h == p.firstPublic && p.verdict == Severity.PASS -> Severity.PASS
                    else -> Severity.INFO
                }
                DetailEntry(
                    source = AppStrings.get(R.string.det_router_hop, tr.target.name, tr.target.ip, h.ttl),
                    reported = reported,
                    verdict = sev,
                )
            }
        }

        val value = per.joinToString("  ·  ") { p ->
            val cc = p.country ?: if (p.firstPublic == null) "—" else unknown
            val mark = when (p.verdict) {
                Severity.PASS -> " ✓"
                Severity.HARD -> " ✗"
                else -> ""
            }
            "${p.target.name}=$cc$mark"
        } + if (simCountry.isNotEmpty()) AppStrings.get(R.string.val_router_sim_suffix, simCountry) else ""

        listOf(
            Check(
                id = "router_egress_country",
                category = Category.PROBES,
                label = AppStrings.get(R.string.check_router_egress_country_label_n, TARGETS.size),
                value = value,
                severity = aggregate,
                explanation = AppStrings.get(
                    R.string.check_router_egress_country_explanation,
                    TARGETS.joinToString { it.ip },
                ),
                details = details,
            )
        )
    }

    private suspend fun traceroute(target: String): List<Hop> = coroutineScope {
        (1..MAX_TTL).map { ttl -> async { ping(ttl, target) } }
            .awaitAll()
            .sortedBy { it.ttl }
    }

    private fun ping(ttl: Int, target: String): Hop {
        return try {
            val pb = ProcessBuilder(
                "/system/bin/ping",
                "-c", "1",
                "-W", "1",
                "-n",
                "-t", ttl.toString(),
                target,
            ).redirectErrorStream(true)
            val p = pb.start()
            val finished = p.waitFor(PING_TIMEOUT_S, TimeUnit.SECONDS)
            if (!finished) {
                p.destroyForcibly()
                return Hop(ttl, null, false)
            }
            val out = p.inputStream.bufferedReader().use { it.readText() }
            val ip = HOP_REGEX.find(out)?.groupValues?.get(1)
            // Final reply has both "bytes from" and "ttl=" in the line.
            val isFinal = out.contains("bytes from") && out.contains("ttl=")
            Hop(ttl, ip, isFinal)
        } catch (e: Exception) {
            Hop(ttl, null, false)
        }
    }

    private fun lookupIpinfo(ip: String): IpinfoLite? = try {
        val req = Request.Builder()
            .url("https://ipinfo.io/$ip/json")
            .header("User-Agent", "vpn-detector/0.5")
            .build()
        Http.client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) null
            else AppJson.decodeFromString(IpinfoLite.serializer(), resp.body?.string().orEmpty())
        }
    } catch (e: Exception) {
        null
    }

    /** RFC1918 + CGNAT + loopback + link-local. */
    private fun isPrivate(ip: String): Boolean {
        val parts = ip.split(".").mapNotNull { it.toIntOrNull() }
        if (parts.size != 4) return false
        val a = parts[0]; val b = parts[1]
        return when {
            a == 10 -> true
            a == 172 && b in 16..31 -> true
            a == 192 && b == 168 -> true
            a == 169 && b == 254 -> true
            a == 127 -> true
            a == 100 && b in 64..127 -> true     // CGNAT 100.64.0.0/10
            else -> false
        }
    }
}
