package ru.shmelev.vpndetector.detect.geoip

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import okhttp3.Request
import ru.shmelev.vpndetector.detect.Category
import ru.shmelev.vpndetector.detect.Check
import ru.shmelev.vpndetector.detect.Severity
import ru.shmelev.vpndetector.net.AppJson
import ru.shmelev.vpndetector.net.Http

/**
 * GeoIP probes (Tab 2). Each probe returns a [ProbeResult]; the engine derives Checks from them.
 */
@Serializable
data class ProbeResult(
    val provider: String,
    val ip: String? = null,
    val country: String? = null,
    val region: String? = null,
    val city: String? = null,
    val asn: String? = null,
    val org: String? = null,
    val isProxy: Boolean? = null,
    val isHosting: Boolean? = null,
    val isVpn: Boolean? = null,
    val timezone: String? = null,
    val error: String? = null,
)

private val DATACENTER_KEYWORDS = listOf(
    "digitalocean", "amazon", "aws", "hetzner", "ovh", "linode",
    "vultr", "choopa", "google llc", "google cloud", "microsoft",
    "azure", "m247", "quadranet", "leaseweb", "cloudflare", "datacamp",
    "contabo", "scaleway", "online sas", "psychz", "hosthatch",
    "vps", "host", "cloud",
)

object GeoIpProbes {

    suspend fun runAll(): List<ProbeResult> = withContext(Dispatchers.IO) {
        coroutineScope {
            listOf(
                async { ipify() },
                async { ipinfo() },
                async { ipApi() },
                async { ifconfigCo() },
                async { myipCom() },
                async { cloudflareTrace() },
            ).awaitAll()
        }
    }

    fun derive(results: List<ProbeResult>): List<Check> {
        val out = mutableListOf<Check>()
        val ok = results.filter { it.error == null && it.ip != null }

        // Per-probe rows
        for (r in results) {
            val v = if (r.error != null) {
                "ERROR: ${r.error}"
            } else {
                "${r.ip ?: "?"} · ${r.country ?: "?"} · ${r.org ?: r.asn ?: "?"}"
            }
            out += Check(
                id = "probe_${r.provider}",
                category = Category.GEOIP,
                label = "Probe: ${r.provider}",
                value = v,
                severity = Severity.INFO,
                explanation = "Raw GeoIP probe result.",
            )
        }

        // External country (canonical)
        val country = ok.map { it.country?.uppercase() }.firstOrNull { !it.isNullOrEmpty() }
        out += Check(
            id = "external_country",
            category = Category.GEOIP,
            label = "External country",
            value = country ?: "?",
            severity = if (country == "RU") Severity.PASS else Severity.INFO,
            explanation = "What the world sees. PASS only on RU. Real verdict comes from Consistency tab.",
        )

        // ASN class
        val org = ok.firstNotNullOfOrNull { it.org } ?: ""
        val isDc = DATACENTER_KEYWORDS.any { org.contains(it, ignoreCase = true) }
        out += Check(
            id = "asn_class",
            category = Category.GEOIP,
            label = "ASN organisation",
            value = org.ifEmpty { "?" },
            severity = if (isDc) Severity.HARD else Severity.PASS,
            explanation = "Datacenter ASNs (DigitalOcean/AWS/Hetzner/OVH/etc.) = HARD VPN signal. " +
                "Residential ISP ASNs are clean.",
        )

        // Reputation flags
        val flagged = ok.any { (it.isProxy == true) || (it.isHosting == true) || (it.isVpn == true) }
        out += Check(
            id = "reputation_flag",
            category = Category.GEOIP,
            label = "Probe reputation flag",
            value = if (flagged) "flagged" else "clean",
            severity = if (flagged) Severity.HARD else Severity.PASS,
            explanation = "Any probe returned proxy/hosting/vpn=true.",
        )

        // Probe disagreement on IP
        val ips = ok.mapNotNull { it.ip }.toSet()
        out += Check(
            id = "probe_ip_agreement",
            category = Category.GEOIP,
            label = "Probe IP agreement",
            value = ips.joinToString(),
            severity = if (ips.size > 1) Severity.HARD else Severity.PASS,
            explanation = "Different probes seeing different external IPs = split routing leak.",
        )

        // Probe disagreement on country (DB lag)
        val countries = ok.mapNotNull { it.country?.uppercase() }.toSet()
        if (countries.size > 1) {
            out += Check(
                id = "probe_country_agreement",
                category = Category.GEOIP,
                label = "Probe country agreement",
                value = countries.joinToString(),
                severity = Severity.SOFT,
                explanation = "Probes returned same IP but different country (GeoIP DB lag).",
            )
        }

        return out
    }

    // ---------- individual probes ----------

    private fun fetch(url: String): String? = runCatching {
        Http.client.newCall(Request.Builder().url(url).header("User-Agent", "vpn-detector/0.1").build())
            .execute().use { resp ->
                if (!resp.isSuccessful) return null
                resp.body?.string()
            }
    }.getOrNull()

    @Serializable private data class IpifyResp(val ip: String? = null)
    private fun ipify(): ProbeResult = try {
        val body = fetch("https://api.ipify.org?format=json") ?: return ProbeResult("ipify", error = "no body")
        val r = AppJson.decodeFromString(IpifyResp.serializer(), body)
        ProbeResult("ipify", ip = r.ip)
    } catch (e: Exception) {
        ProbeResult("ipify", error = e.message ?: "error")
    }

    @Serializable private data class IpinfoResp(
        val ip: String? = null,
        val country: String? = null,
        val region: String? = null,
        val city: String? = null,
        val org: String? = null,
        val timezone: String? = null,
    )
    private fun ipinfo(): ProbeResult = try {
        val body = fetch("https://ipinfo.io/json") ?: return ProbeResult("ipinfo", error = "no body")
        val r = AppJson.decodeFromString(IpinfoResp.serializer(), body)
        ProbeResult("ipinfo", ip = r.ip, country = r.country, region = r.region, city = r.city,
            org = r.org, asn = r.org?.substringBefore(" "), timezone = r.timezone)
    } catch (e: Exception) {
        ProbeResult("ipinfo", error = e.message ?: "error")
    }

    @Serializable private data class IpApiResp(
        val query: String? = null,
        val countryCode: String? = null,
        val regionName: String? = null,
        val city: String? = null,
        val isp: String? = null,
        val org: String? = null,
        val `as`: String? = null,
        val proxy: Boolean? = null,
        val hosting: Boolean? = null,
        val mobile: Boolean? = null,
        val timezone: String? = null,
    )
    private fun ipApi(): ProbeResult = try {
        val body = fetch("http://ip-api.com/json/?fields=status,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query,timezone")
            ?: return ProbeResult("ip-api", error = "no body")
        val r = AppJson.decodeFromString(IpApiResp.serializer(), body)
        ProbeResult("ip-api", ip = r.query, country = r.countryCode, region = r.regionName, city = r.city,
            org = r.isp ?: r.org, asn = r.`as`, isProxy = r.proxy, isHosting = r.hosting, timezone = r.timezone)
    } catch (e: Exception) {
        ProbeResult("ip-api", error = e.message ?: "error")
    }

    @Serializable private data class IfconfigCoResp(
        val ip: String? = null,
        val country_iso: String? = null,
        val region_name: String? = null,
        val city: String? = null,
        val asn: String? = null,
        val asn_org: String? = null,
        val time_zone: String? = null,
    )
    private fun ifconfigCo(): ProbeResult = try {
        val body = fetch("https://ifconfig.co/json") ?: return ProbeResult("ifconfig.co", error = "no body")
        val r = AppJson.decodeFromString(IfconfigCoResp.serializer(), body)
        ProbeResult("ifconfig.co", ip = r.ip, country = r.country_iso, region = r.region_name,
            city = r.city, asn = r.asn, org = r.asn_org, timezone = r.time_zone)
    } catch (e: Exception) {
        ProbeResult("ifconfig.co", error = e.message ?: "error")
    }

    @Serializable private data class MyipResp(
        val ip: String? = null,
        val country: String? = null,
        val cc: String? = null,
    )
    private fun myipCom(): ProbeResult = try {
        val body = fetch("https://api.myip.com") ?: return ProbeResult("myip.com", error = "no body")
        val r = AppJson.decodeFromString(MyipResp.serializer(), body)
        ProbeResult("myip.com", ip = r.ip, country = r.cc ?: r.country)
    } catch (e: Exception) {
        ProbeResult("myip.com", error = e.message ?: "error")
    }

    private fun cloudflareTrace(): ProbeResult = try {
        val body = fetch("https://www.cloudflare.com/cdn-cgi/trace") ?: return ProbeResult("cf-trace", error = "no body")
        val map = body.lineSequence().mapNotNull {
            val i = it.indexOf('='); if (i <= 0) null else it.substring(0, i) to it.substring(i + 1)
        }.toMap()
        val warp = map["warp"] == "on" || map["gateway"] == "on"
        ProbeResult("cf-trace", ip = map["ip"], country = map["loc"],
            isVpn = if (warp) true else null)
    } catch (e: Exception) {
        ProbeResult("cf-trace", error = e.message ?: "error")
    }
}
