package net.vpndetector.detect.geoip

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
    /** Forwarding-style headers observed on this probe's HTTP response. */
    val proxyHeaders: Map<String, String> = emptyMap(),
) {
    val isIpv6: Boolean get() = ip?.contains(":") == true
    val isIpv4: Boolean get() = ip != null && !ip.contains(":")
}

private val DATACENTER_KEYWORDS = listOf(
    "digitalocean", "amazon", "aws", "hetzner", "ovh", "linode",
    "vultr", "choopa", "google llc", "google cloud", "microsoft",
    "azure", "m247", "quadranet", "leaseweb", "cloudflare", "datacamp",
    "contabo", "scaleway", "online sas", "psychz", "hosthatch",
    "vps", "host", "cloud",
)

/**
 * CDN organisations whose IPs and ASNs legitimately appear in front of millions of legitimate
 * customer apps. Methodology §4 explicitly calls out CDN whitelisting as a false-positive mitigation.
 * If the org name matches both a datacenter keyword AND a CDN keyword we demote `asn_class` from
 * HARD to INFO instead of flagging the user as on-VPN.
 */
private val CDN_KEYWORDS = listOf(
    "cloudflare", "akamai", "fastly", "cloudfront", "google", "incapsula",
    "stackpath", "bunnycdn", "keycdn", "azure cdn", "azure front door",
)

/** Forwarding-style HTTP headers that, when present in a probe response, indicate a transparent
 *  proxy or middlebox is rewriting the request in flight. Methodology §10.2. */
private val PROXY_HEADER_NAMES = listOf("via", "x-forwarded-for", "forwarded", "x-real-ip")

/**
 * Known-legitimate service-side header values. Methodology §10.2 explicitly warns that
 * services and CDNs may legitimately add these headers themselves, so a match here must
 * be whitelisted to avoid false positives.
 *
 * Each entry is a substring (case-insensitive) that, when found in a response header
 * *value*, is treated as the service's own infrastructure and downgraded to INFO.
 *
 * - "1.1 google"  Google Cloud Load Balancer adds this to every response it proxies
 *                 (e.g. ipinfo.io runs on GCP and its responses carry `Via: 1.1 google`).
 * - "varnish"     Fastly / self-hosted Varnish caches.
 * - "cloudfront"  AWS CloudFront.
 * - "akamaighost" Akamai.
 * - "nginx"       Service running its own nginx reverse proxy — not a MITM on the path.
 * - "cloudflare"  Cloudflare's own edge.
 * - "envoy"       Envoy-based service meshes.
 */
private val LEGITIMATE_SERVICE_HEADER_MARKERS = listOf(
    "1.1 google", "varnish", "cloudfront", "akamaighost", "akamai",
    "nginx", "cloudflare", "envoy", "apache", "haproxy",
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
                async { yandexIpv4() },
                async { yandexIpv6() },
                async { ifconfigMe() },
                async { checkipAws() },
                async { ipMailRu() },
                async { ipApiV6() },
                async { dnsResolverEgress() },
            ).awaitAll()
        }
    }

    /** Providers whose IP is NOT the v4 HTTP exit. Excluded from all aggregation checks;
     *  their egresses are compared in dedicated Consistency checks instead. */
    internal val AGGREGATION_EXCLUDED = setOf("ip-api-v6", "resolver-egress", "yandex-v6")

    fun derive(results: List<ProbeResult>): List<Check> {
        val out = mutableListOf<Check>()
        val ok = results.filter { it.error == null && it.ip != null }
        val okV4 = ok.filter { it.provider !in AGGREGATION_EXCLUDED && it.isIpv4 }

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

        // External country (canonical) — only v4 HTTP-exit probes; v6/resolver-egress live in Consistency.
        val country = okV4.map { it.country?.uppercase() }.firstOrNull { !it.isNullOrEmpty() }
        out += Check(
            id = "external_country",
            category = Category.GEOIP,
            label = "External country",
            value = country ?: "?",
            severity = if (country == "RU") Severity.PASS else Severity.INFO,
            explanation = "What the world sees. PASS only on RU. Real verdict comes from Consistency tab.",
        )

        // ASN class — short value, per-probe org breakdown in details.
        // CDN whitelist (methodology §4): if the org matches both a datacenter keyword
        // AND a CDN keyword, demote the entire row from HARD to INFO. CDNs legitimately
        // front millions of customer apps and would otherwise produce a flood of false
        // positives.
        val asnDetails = results.map { p ->
            val org = p.org ?: p.asn
            val dcMatch = if (org != null) {
                DATACENTER_KEYWORDS.firstOrNull { org.contains(it, ignoreCase = true) }
            } else null
            val cdnMatch = if (org != null) {
                CDN_KEYWORDS.firstOrNull { org.contains(it, ignoreCase = true) }
            } else null
            val excluded = p.provider in AGGREGATION_EXCLUDED
            val verdict = when {
                p.error != null -> Severity.INFO
                org == null -> Severity.INFO
                excluded -> Severity.INFO             // v6 / resolver-egress scored in Consistency
                cdnMatch != null -> Severity.INFO     // CDN whitelist wins over datacenter match
                dcMatch != null -> Severity.HARD
                else -> Severity.PASS
            }
            val reported = when {
                p.error != null -> "ERROR: ${p.error}"
                org == null -> "(no org field)"
                excluded && dcMatch != null -> "$org  ←  \"$dcMatch\" (excluded: compared in Consistency)"
                excluded -> "$org  (excluded: compared in Consistency)"
                cdnMatch != null -> "$org  ←  CDN whitelist (\"$cdnMatch\")"
                dcMatch != null -> "$org  ←  matched \"$dcMatch\""
                else -> org
            }
            DetailEntry(source = p.provider, reported = reported, verdict = verdict)
        }
        val isDc = asnDetails.any { it.verdict == Severity.HARD }
        val firstOrg = okV4.firstNotNullOfOrNull { it.org } ?: "?"
        out += Check(
            id = "asn_class",
            category = Category.GEOIP,
            label = "ASN organisation",
            value = firstOrg,
            severity = if (isDc) Severity.HARD else Severity.PASS,
            explanation = "Datacenter ASNs (DigitalOcean/AWS/Hetzner/OVH/etc.) = HARD VPN signal. " +
                "Residential ISP ASNs are clean. CDN ASNs (Cloudflare, Akamai, Fastly, CloudFront) " +
                "are whitelisted to suppress false positives. Tap to see what each probe returned.",
            details = asnDetails,
        )

        // Reputation flags — short value, per-probe flag breakdown in details
        val repDetails = results.map { p ->
            val fields = buildList {
                if (p.isProxy == true) add("proxy=true")
                if (p.isHosting == true) add("hosting=true")
                if (p.isVpn == true) add("vpn=true")
                if (p.isProxy == false) add("proxy=false")
                if (p.isHosting == false) add("hosting=false")
                if (p.isVpn == false) add("vpn=false")
            }
            val excluded = p.provider in AGGREGATION_EXCLUDED
            val verdict = when {
                p.error != null -> Severity.INFO
                excluded -> Severity.INFO
                p.isProxy == true || p.isHosting == true || p.isVpn == true -> Severity.HARD
                fields.isEmpty() -> Severity.INFO
                else -> Severity.PASS
            }
            val reported = when {
                p.error != null -> "ERROR: ${p.error}"
                fields.isEmpty() -> "(provider does not expose proxy/hosting/vpn fields)"
                else -> fields.joinToString(", ")
            }
            DetailEntry(source = p.provider, reported = reported, verdict = verdict)
        }
        val flagged = repDetails.any { it.verdict == Severity.HARD }
        out += Check(
            id = "reputation_flag",
            category = Category.GEOIP,
            label = "Probe reputation flag",
            value = if (flagged) "flagged" else "clean",
            severity = if (flagged) Severity.HARD else Severity.PASS,
            explanation = "Anti-fraud flag from a GeoIP probe. ip-api.com returns proxy/hosting; " +
                "Cloudflare cdn-cgi/trace exposes warp=on/gateway=on (treated as vpn=true). " +
                "Tap to see which provider returned what.",
            details = repDetails,
        )

        // Probe disagreement on IP — short value, per-probe IP in details. Only compare the
        // v4 HTTP-exit probes; v6 and resolver-egress are structurally different IPs.
        val ipDetails = results.map { p ->
            val excluded = p.provider in AGGREGATION_EXCLUDED
            DetailEntry(
                source = p.provider,
                reported = when {
                    p.error != null -> "ERROR: ${p.error}"
                    p.ip == null -> "?"
                    excluded -> "${p.ip}  (excluded from agreement check)"
                    else -> p.ip
                },
                verdict = if (p.error != null || p.ip == null || excluded) Severity.INFO else Severity.PASS,
            )
        }
        val ips = okV4.mapNotNull { it.ip }.toSet()
        out += Check(
            id = "probe_ip_agreement",
            category = Category.GEOIP,
            label = "Probe IP agreement",
            value = if (ips.size <= 1) ips.firstOrNull() ?: "?" else "${ips.size} different IPs",
            severity = if (ips.size > 1) Severity.HARD else Severity.PASS,
            explanation = "Different probes seeing different external IPs = split routing leak.",
            details = ipDetails,
        )

        // Probe disagreement on country (DB lag) — v4 HTTP-exit probes only.
        val countries = okV4.mapNotNull { it.country?.uppercase() }.toSet()
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

        // Transparent proxy headers (methodology §10.2). Forwarding-style HTTP headers added
        // to a probe response by an in-flight middlebox. Since we connect directly to the
        // GeoIP services with no proxy, an UNKNOWN header value would mean a transparent
        // proxy on the path is rewriting the request. But the methodology itself warns:
        // 'сам сервис или CDN также может легитимно формировать часть таких заголовков'.
        // Real-world example: ipinfo.io runs on Google Cloud Load Balancer which adds
        // `Via: 1.1 google` to every response — that's the service's own infrastructure,
        // not a MITM on the user's path. We whitelist known service-side markers and
        // only flag header values that fall outside the whitelist.
        fun isLegitimateServiceHeader(value: String): Boolean =
            LEGITIMATE_SERVICE_HEADER_MARKERS.any { value.contains(it, ignoreCase = true) }

        val headerHits = results.flatMap { p ->
            p.proxyHeaders
                .filter { (_, v) -> !isLegitimateServiceHeader(v) }
                .map { (k, v) -> Triple(p.provider, k, v) }
        }
        val headerDetails = results.map { p ->
            val hits = p.proxyHeaders
            val unknownHits = hits.filter { (_, v) -> !isLegitimateServiceHeader(v) }
            val knownHits = hits.filter { (_, v) -> isLegitimateServiceHeader(v) }
            val (reported, sev) = when {
                p.error != null -> "ERROR: ${p.error}" to Severity.INFO
                hits.isEmpty() -> "no forwarding headers" to Severity.PASS
                unknownHits.isNotEmpty() -> {
                    val u = unknownHits.entries.joinToString { "${it.key}=${it.value}" }
                    val k = if (knownHits.isEmpty()) "" else " (also: " + knownHits.entries
                        .joinToString { "${it.key}=${it.value}" } + " — service-side, ignored)"
                    "$u$k" to Severity.HARD
                }
                else -> {
                    // Only known service-side markers: ipinfo on GCLB, etc. Not a path proxy.
                    knownHits.entries.joinToString { "${it.key}=${it.value}" } +
                        "  (service-side, whitelisted)" to Severity.PASS
                }
            }
            DetailEntry(source = p.provider, reported = reported, verdict = sev)
        }
        out += Check(
            id = "transparent_proxy_headers",
            category = Category.GEOIP,
            label = "Transparent proxy headers",
            value = if (headerHits.isEmpty()) "none (or all whitelisted)" else "${headerHits.size} unknown hits",
            severity = if (headerHits.isNotEmpty()) Severity.HARD else Severity.PASS,
            explanation = "Methodology §10.2 — Via / X-Forwarded-For / Forwarded headers added " +
                "to probe responses indicate a transparent proxy on the path. Known service-side " +
                "infrastructure (Google Cloud LB 'via=1.1 google', Fastly varnish, CloudFront, " +
                "Akamai, nginx, Cloudflare, Envoy, etc.) is whitelisted because the methodology " +
                "itself warns those are legitimately added by the service or its CDN.",
            details = headerDetails,
        )

        return out
    }

    // ---------- individual probes ----------

    private data class Fetched(val body: String?, val proxyHeaders: Map<String, String>)

    private fun fetch(url: String): Fetched = runCatching {
        Http.client.newCall(Request.Builder().url(url).header("User-Agent", "vpn-detector/0.4").build())
            .execute().use { resp ->
                val proxyHeaders = PROXY_HEADER_NAMES.mapNotNull { name ->
                    resp.header(name)?.let { name to it }
                }.toMap()
                if (!resp.isSuccessful) Fetched(null, proxyHeaders)
                else Fetched(resp.body?.string(), proxyHeaders)
            }
    }.getOrElse { Fetched(null, emptyMap()) }

    @Serializable private data class IpifyResp(val ip: String? = null)
    private fun ipify(): ProbeResult = try {
        val f = fetch("https://api.ipify.org?format=json")
        val body = f.body ?: return ProbeResult("ipify", error = "no body", proxyHeaders = f.proxyHeaders)
        val r = AppJson.decodeFromString(IpifyResp.serializer(), body)
        ProbeResult("ipify", ip = r.ip, proxyHeaders = f.proxyHeaders)
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
        val f = fetch("https://ipinfo.io/json")
        val body = f.body ?: return ProbeResult("ipinfo", error = "no body", proxyHeaders = f.proxyHeaders)
        val r = AppJson.decodeFromString(IpinfoResp.serializer(), body)
        ProbeResult("ipinfo", ip = r.ip, country = r.country, region = r.region, city = r.city,
            org = r.org, asn = r.org?.substringBefore(" "), timezone = r.timezone,
            proxyHeaders = f.proxyHeaders)
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
        // ip-api free tier is HTTP-only; cleartext for this host is allowed via network_security_config.xml
        val f = fetch("http://ip-api.com/json/?fields=status,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query,timezone")
        val body = f.body ?: return ProbeResult("ip-api", error = "no body", proxyHeaders = f.proxyHeaders)
        val r = AppJson.decodeFromString(IpApiResp.serializer(), body)
        ProbeResult("ip-api", ip = r.query, country = r.countryCode, region = r.regionName, city = r.city,
            org = r.isp ?: r.org, asn = r.`as`, isProxy = r.proxy, isHosting = r.hosting,
            timezone = r.timezone, proxyHeaders = f.proxyHeaders)
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
        val f = fetch("https://ifconfig.co/json")
        val body = f.body ?: return ProbeResult("ifconfig.co", error = "no body", proxyHeaders = f.proxyHeaders)
        val r = AppJson.decodeFromString(IfconfigCoResp.serializer(), body)
        ProbeResult("ifconfig.co", ip = r.ip, country = r.country_iso, region = r.region_name,
            city = r.city, asn = r.asn, org = r.asn_org, timezone = r.time_zone,
            proxyHeaders = f.proxyHeaders)
    } catch (e: Exception) {
        ProbeResult("ifconfig.co", error = e.message ?: "error")
    }

    @Serializable private data class MyipResp(
        val ip: String? = null,
        val country: String? = null,
        val cc: String? = null,
    )
    private fun myipCom(): ProbeResult = try {
        val f = fetch("https://api.myip.com")
        val body = f.body ?: return ProbeResult("myip.com", error = "no body", proxyHeaders = f.proxyHeaders)
        val r = AppJson.decodeFromString(MyipResp.serializer(), body)
        ProbeResult("myip.com", ip = r.ip, country = r.cc ?: r.country, proxyHeaders = f.proxyHeaders)
    } catch (e: Exception) {
        ProbeResult("myip.com", error = e.message ?: "error")
    }

    private val IPV4_REGEX = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b""")
    private val IPV6_REGEX = Regex("""(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}""")

    /** Additional external-IP discovery endpoints documented in public anti-fraud research
     *  as canonical checkers used by RU-facing apps. We mirror them so users can see what
     *  the same checkers see. Responses are either JSON (Yandex) or plain text with the IP;
     *  we regex-extract to tolerate both. */
    private fun yandexIpv4(): ProbeResult = try {
        val f = fetch("https://ipv4-internet.yandex.net/api/v0/ip")
        val body = f.body ?: return ProbeResult("yandex-v4", error = "no body", proxyHeaders = f.proxyHeaders)
        val ip = IPV4_REGEX.find(body)?.value
        ProbeResult("yandex-v4", ip = ip, proxyHeaders = f.proxyHeaders)
    } catch (e: Exception) {
        ProbeResult("yandex-v4", error = e.message ?: "error")
    }

    private fun yandexIpv6(): ProbeResult = try {
        val f = fetch("https://ipv6-internet.yandex.net/api/v0/ip")
        val body = f.body ?: return ProbeResult("yandex-v6", error = "no body", proxyHeaders = f.proxyHeaders)
        val ip = IPV6_REGEX.find(body)?.value ?: IPV4_REGEX.find(body)?.value
        ProbeResult("yandex-v6", ip = ip, proxyHeaders = f.proxyHeaders)
    } catch (e: Exception) {
        ProbeResult("yandex-v6", error = e.message ?: "error")
    }

    private fun ifconfigMe(): ProbeResult = try {
        val f = fetch("https://ifconfig.me/ip")
        val body = f.body?.trim()
        if (body.isNullOrEmpty()) ProbeResult("ifconfig.me", error = "no body", proxyHeaders = f.proxyHeaders)
        else {
            val ip = IPV6_REGEX.find(body)?.value ?: IPV4_REGEX.find(body)?.value ?: body
            ProbeResult("ifconfig.me", ip = ip, proxyHeaders = f.proxyHeaders)
        }
    } catch (e: Exception) {
        ProbeResult("ifconfig.me", error = e.message ?: "error")
    }

    private fun checkipAws(): ProbeResult = try {
        val f = fetch("https://checkip.amazonaws.com/")
        val body = f.body?.trim()
        if (body.isNullOrEmpty()) ProbeResult("aws-checkip", error = "no body", proxyHeaders = f.proxyHeaders)
        else ProbeResult("aws-checkip", ip = IPV4_REGEX.find(body)?.value ?: body, proxyHeaders = f.proxyHeaders)
    } catch (e: Exception) {
        ProbeResult("aws-checkip", error = e.message ?: "error")
    }

    private fun ipMailRu(): ProbeResult = try {
        val f = fetch("https://ip.mail.ru/")
        val body = f.body ?: return ProbeResult("ip.mail.ru", error = "no body", proxyHeaders = f.proxyHeaders)
        val ip = IPV4_REGEX.find(body)?.value
        ProbeResult("ip.mail.ru", ip = ip, proxyHeaders = f.proxyHeaders)
    } catch (e: Exception) {
        ProbeResult("ip.mail.ru", error = e.message ?: "error")
    }

    /**
     * Geolocate the device's IPv6 exit. Router VPNs typically tunnel IPv4 only — if IPv6 is
     * reachable it usually egresses via the native ISP, producing a v4/v6 split. We fetch the
     * v6 address from api6.ipify.org (IPv6-only hostname forces a direct v6 path) and then
     * resolve its geo via ip-api.com, which accepts arbitrary-IP lookups on the free tier.
     */
    private fun ipApiV6(): ProbeResult = try {
        val v6Fetched = fetch("https://api6.ipify.org?format=json")
        val v6 = runCatching {
            AppJson.decodeFromString(IpifyResp.serializer(), v6Fetched.body.orEmpty()).ip
        }.getOrNull()
        if (v6.isNullOrBlank()) {
            ProbeResult("ip-api-v6", error = "no IPv6 reachable")
        } else {
            val f = fetch("http://ip-api.com/json/$v6?fields=status,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query,timezone")
            val body = f.body
                ?: return ProbeResult("ip-api-v6", ip = v6, error = "geo lookup failed", proxyHeaders = f.proxyHeaders)
            val r = AppJson.decodeFromString(IpApiResp.serializer(), body)
            ProbeResult(
                provider = "ip-api-v6",
                ip = r.query ?: v6,
                country = r.countryCode,
                region = r.regionName,
                city = r.city,
                org = r.isp ?: r.org,
                asn = r.`as`,
                isProxy = r.proxy,
                isHosting = r.hosting,
                timezone = r.timezone,
                proxyHeaders = f.proxyHeaders,
            )
        }
    } catch (e: Exception) {
        ProbeResult("ip-api-v6", error = e.message ?: "error")
    }

    /**
     * Resolve `whoami.akamai.net` via the system DNS resolver. Akamai's authoritative server
     * returns an A record whose value is the egress IP of the recursive resolver that made
     * the query — i.e. the IP the DNS traffic actually exits from. We then geolocate that IP.
     *
     * Mismatch between this resolver-egress country/ASN and the HTTP-exit country/ASN is a
     * classic DNS leak signature: VPN tunnels HTTP but DNS bypasses the tunnel (or vice
     * versa). Also catches router-side DNS interception that rewrites queries to a
     * different upstream than the VPN would use.
     */
    private fun dnsResolverEgress(): ProbeResult = try {
        val resolverIp = runCatching {
            java.net.InetAddress.getAllByName("whoami.akamai.net")
                .firstOrNull { it is java.net.Inet4Address }
                ?.hostAddress
        }.getOrNull()
        if (resolverIp.isNullOrBlank()) {
            ProbeResult("resolver-egress", error = "whoami.akamai.net unresolvable")
        } else {
            val f = fetch("http://ip-api.com/json/$resolverIp?fields=status,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query,timezone")
            val body = f.body
                ?: return ProbeResult("resolver-egress", ip = resolverIp, error = "geo lookup failed", proxyHeaders = f.proxyHeaders)
            val r = AppJson.decodeFromString(IpApiResp.serializer(), body)
            ProbeResult(
                provider = "resolver-egress",
                ip = r.query ?: resolverIp,
                country = r.countryCode,
                region = r.regionName,
                city = r.city,
                org = r.isp ?: r.org,
                asn = r.`as`,
                isProxy = r.proxy,
                isHosting = r.hosting,
                timezone = r.timezone,
                proxyHeaders = f.proxyHeaders,
            )
        }
    } catch (e: Exception) {
        ProbeResult("resolver-egress", error = e.message ?: "error")
    }

    private fun cloudflareTrace(): ProbeResult = try {
        val f = fetch("https://www.cloudflare.com/cdn-cgi/trace")
        val body = f.body ?: return ProbeResult("cf-trace", error = "no body", proxyHeaders = f.proxyHeaders)
        val map = body.lineSequence().mapNotNull {
            val i = it.indexOf('='); if (i <= 0) null else it.substring(0, i) to it.substring(i + 1)
        }.toMap()
        val warp = map["warp"] == "on" || map["gateway"] == "on"
        ProbeResult("cf-trace", ip = map["ip"], country = map["loc"],
            isVpn = if (warp) true else null, proxyHeaders = f.proxyHeaders)
    } catch (e: Exception) {
        ProbeResult("cf-trace", error = e.message ?: "error")
    }
}
