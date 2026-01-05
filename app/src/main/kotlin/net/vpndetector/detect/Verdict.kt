package net.vpndetector.detect

import kotlinx.serialization.Serializable

@Serializable
enum class VerdictLevel { CLEAN, SUSPICIOUS, DETECTED }

/** Three-class decision label derived from GeoIP / Direct / Indirect axis grouping. */
@Serializable
enum class MatrixLabel {
    BYPASS_NOT_DETECTED,
    NEEDS_REVIEW,
    BYPASS_DETECTED,
}

@Serializable
data class Verdict(
    val level: VerdictLevel,
    val score: Int,
    val hardCount: Int,
    val softCount: Int,
    val matrix: MatrixLabel = MatrixLabel.BYPASS_NOT_DETECTED,
    val matrixGeoip: Boolean = false,
    val matrixDirect: Boolean = false,
    val matrixIndirect: Boolean = false,
)

object VerdictAggregator {

    /** Direct on-device VPN/proxy signals. */
    private val DIRECT_IDS = setOf(
        "transport_vpn", "cap_not_vpn", "tun_iface", "active_iface_name",
        "default_route_tun", "http_proxy", "jvm_proxy", "vpn_transport_info",
        "dumpsys_vpn", "local_proxy_listeners", "anti_detection_apps",
    )

    /** Indirect / supporting signals. */
    private val INDIRECT_IDS = setOf(
        "private_dns", "dns_servers", "mtu", "route_anomalies", "always_on_vpn",
        "installed_vpn_apps", "telegram_present", "root", "mock_location",
        "lat_ru", "lat_foreign", "lat_ratio", "lat_global", "router_egress_country",
        "transparent_proxy_headers",
    )

    /** GeoIP-stage signals plus consistency cross-checks. */
    private val GEOIP_IDS = setOf(
        "asn_class", "reputation_flag", "probe_ip_agreement", "probe_country_agreement",
        "country_history",
        "sim_vs_ip", "net_vs_ip", "carrier_vs_asn", "mcc_vs_ip",
        "locale_vs_ip", "lang_vs_ip", "tz_vs_ip", "cis_apps",
    )

    fun aggregate(checks: List<Check>): Verdict {
        var score = 0
        var hard = 0
        var soft = 0
        for (c in checks) {
            when (c.severity) {
                Severity.HARD -> { score += 100; hard++ }
                Severity.SOFT -> { score += 10; soft++ }
                else -> {}
            }
        }
        val level = when {
            score >= 100 -> VerdictLevel.DETECTED
            score >= 30 -> VerdictLevel.SUSPICIOUS
            else -> VerdictLevel.CLEAN
        }

        val geoipFired = checks.any { it.severity == Severity.HARD && it.id in GEOIP_IDS }
        val directFired = checks.any { it.severity == Severity.HARD && it.id in DIRECT_IDS }
        val indirectFired = checks.any { it.severity == Severity.HARD && it.id in INDIRECT_IDS }

        val firedCount = listOf(geoipFired, directFired, indirectFired).count { it }
        val matrix = when {
            firedCount >= 2 -> MatrixLabel.BYPASS_DETECTED
            firedCount == 1 && geoipFired -> MatrixLabel.NEEDS_REVIEW
            firedCount == 1 -> MatrixLabel.BYPASS_NOT_DETECTED
            else -> MatrixLabel.BYPASS_NOT_DETECTED
        }

        return Verdict(
            level = level, score = score, hardCount = hard, softCount = soft,
            matrix = matrix, matrixGeoip = geoipFired, matrixDirect = directFired, matrixIndirect = indirectFired,
        )
    }
}
