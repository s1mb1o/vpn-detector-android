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
 * to a foreign anchor (1.1.1.1). Path A from `docs/specs/04_proposed-checks.md`:
 * unprivileged ICMP socket, no root, no permissions beyond INTERNET.
 *
 * Verdict rule: if the **first non-RFC1918 hop's country** differs from the
 * SIM country, the device's egress is via a router-side VPN tunnel.
 */
object Traceroute {

    private const val TARGET = "1.1.1.1"
    private const val MAX_TTL = 15
    private const val PING_TIMEOUT_S = 2L
    private val HOP_REGEX = Regex("""(?:From\s+|bytes from\s+)(\d{1,3}(?:\.\d{1,3}){3})""")

    @Serializable
    private data class IpinfoLite(
        val ip: String? = null,
        val country: String? = null,
        val city: String? = null,
        val org: String? = null,
    )

    private data class Hop(val ttl: Int, val ip: String?, val isFinal: Boolean)

    suspend fun run(ctx: Context): List<Check> = withContext(Dispatchers.IO) {
        val rawHops = traceroute()

        if (rawHops.all { it.ip == null }) {
            return@withContext listOf(
                Check(
                    id = "router_egress_country",
                    category = Category.PROBES,
                    label = "Router egress traceroute",
                    value = "no hops returned",
                    severity = Severity.INFO,
                    explanation = "Some carrier networks drop ICMP TTL exceeded entirely, " +
                        "so traceroute cannot map the path on this connection.",
                )
            )
        }

        // Trim hops at the first final reply (don't show ghosts past the destination)
        val finalIdx = rawHops.indexOfFirst { it.isFinal }
        val hops = if (finalIdx >= 0) rawHops.take(finalIdx + 1) else rawHops

        val firstPublic = hops.firstOrNull { it.ip != null && !isPrivate(it.ip) }
        val publicIps = hops.mapNotNull { it.ip }.filter { !isPrivate(it) }.distinct()
        val ipinfo = publicIps.associateWith { lookupIpinfo(it) }

        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        val simCountry = (tm?.simCountryIso?.takeIf { it.isNotEmpty() }
            ?: tm?.networkCountryIso.orEmpty()).uppercase()

        val firstPublicCountry = firstPublic?.ip?.let { ipinfo[it]?.country?.uppercase() }

        val verdict: Severity = when {
            firstPublic == null -> Severity.INFO
            simCountry.isEmpty() || firstPublicCountry == null -> Severity.INFO
            firstPublicCountry == simCountry -> Severity.PASS
            else -> Severity.HARD
        }

        val details = hops.map { h ->
            val info = h.ip?.let { ipinfo[it] }
            val reported = when {
                h.ip == null -> "* (no reply)"
                isPrivate(h.ip) -> "${h.ip}  (private)"
                info == null -> "${h.ip}  (geoip lookup failed)"
                else -> "${h.ip}  ${info.country ?: "?"}  ${info.city.orEmpty()}  ${info.org.orEmpty()}".trim()
            }
            val sev = when {
                h.ip == null -> Severity.INFO
                isPrivate(h.ip) -> Severity.INFO
                info?.country == null -> Severity.INFO
                h == firstPublic && firstPublicCountry != null && simCountry.isNotEmpty()
                    && firstPublicCountry != simCountry -> Severity.HARD
                info.country.uppercase() == simCountry -> Severity.PASS
                else -> Severity.INFO
            }
            DetailEntry(source = "hop ${h.ttl}", reported = reported, verdict = sev)
        }

        val value = when {
            firstPublic == null -> "no public hop reached"
            verdict == Severity.HARD -> "${firstPublic.ip} = $firstPublicCountry  ≠  SIM=$simCountry"
            verdict == Severity.PASS -> "${firstPublic.ip} = $firstPublicCountry  ✓"
            else -> firstPublic.ip ?: "?"
        }

        listOf(
            Check(
                id = "router_egress_country",
                category = Category.PROBES,
                label = "Router egress traceroute",
                value = value,
                severity = verdict,
                explanation = "Maps the L3 path to $TARGET via /system/bin/ping -t N. " +
                    "Rule: the first non-RFC1918 hop's country must match the SIM country. " +
                    "If it differs, the device's traffic is exiting through a router-side VPN. " +
                    "Tap to see every hop, including the private ones inside the router.",
                details = details,
            )
        )
    }

    private suspend fun traceroute(): List<Hop> = coroutineScope {
        (1..MAX_TTL).map { ttl -> async { ping(ttl) } }
            .awaitAll()
            .sortedBy { it.ttl }
    }

    private fun ping(ttl: Int): Hop {
        return try {
            val pb = ProcessBuilder(
                "/system/bin/ping",
                "-c", "1",
                "-W", "1",
                "-n",
                "-t", ttl.toString(),
                TARGET,
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
            .header("User-Agent", "vpn-detector/0.3")
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
