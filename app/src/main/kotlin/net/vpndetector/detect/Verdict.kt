package net.vpndetector.detect

import kotlinx.serialization.Serializable

@Serializable
enum class VerdictLevel { CLEAN, SUSPICIOUS, DETECTED }

/** Methodology §9 — Table 2 — three-class decision label derived from the
 *  GeoIP / Direct / Indirect axis grouping. Distinct from the score-based
 *  [VerdictLevel]: this one mirrors the methodology document's exact wording. */
@Serializable
enum class MatrixLabel {
    /** "Обход не выявлен" — no signal triggered, OR a single check on its own. */
    BYPASS_NOT_DETECTED,
    /** "Требуется дополнительная проверка" — two of three axes triggered with conflicts. */
    NEEDS_REVIEW,
    /** "Обход выявлен" — at least two axes consistently agree. */
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

    /** Direct on-device VPN/proxy signals. Methodology §6: explicit system flags. */
    private val DIRECT_IDS = setOf(
        "transport_vpn", "cap_not_vpn", "tun_iface", "active_iface_name",
        "default_route_tun", "http_proxy", "jvm_proxy", "vpn_transport_info",
        "dumpsys_vpn", "local_proxy_listeners",
    )

    /** Indirect / supporting signals. Methodology §7. */
    private val INDIRECT_IDS = setOf(
        "private_dns", "dns_servers", "mtu", "route_anomalies", "always_on_vpn",
        "installed_vpn_apps", "telegram_present", "root", "mock_location",
        "lat_ru", "lat_foreign", "lat_ratio", "router_egress_country",
        "transparent_proxy_headers",
    )

    /** GeoIP-stage signals (server-side analog from §5) we can produce client-side,
     *  PLUS the consistency cross-checks that compare local context against the IP. */
    private val GEOIP_IDS = setOf(
        "asn_class", "reputation_flag", "probe_ip_agreement", "probe_country_agreement",
        "country_history",
        // Consistency cross-checks are server-side-equivalent — they ask "does the
        // GeoIP-claimed location match the device's other observable facts".
        "sim_vs_ip", "net_vs_ip", "carrier_vs_asn", "mcc_vs_ip",
        "locale_vs_ip", "lang_vs_ip", "tz_vs_ip", "ru_apps",
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

        // Methodology §9 matrix axes — each axis "fires" if ANY of its checks reported HARD.
        val geoipFired = checks.any { it.severity == Severity.HARD && it.id in GEOIP_IDS }
        val directFired = checks.any { it.severity == Severity.HARD && it.id in DIRECT_IDS }
        val indirectFired = checks.any { it.severity == Severity.HARD && it.id in INDIRECT_IDS }

        // Decision matrix — derived directly from Table 2 in the methodology.
        // Two or more axes agree → BYPASS_DETECTED
        // One axis fires alone → NEEDS_REVIEW (or CLEAN if it's GeoIP only — methodology says
        //   server-only result with clean client = "additional check required")
        // Zero axes → BYPASS_NOT_DETECTED
        val firedCount = listOf(geoipFired, directFired, indirectFired).count { it }
        val matrix = when {
            firedCount >= 2 -> MatrixLabel.BYPASS_DETECTED
            firedCount == 1 && geoipFired -> MatrixLabel.NEEDS_REVIEW
            firedCount == 1 -> MatrixLabel.BYPASS_NOT_DETECTED
            else -> MatrixLabel.BYPASS_NOT_DETECTED
        }

        return Verdict(
            level = level,
            score = score,
            hardCount = hard,
            softCount = soft,
            matrix = matrix,
            matrixGeoip = geoipFired,
            matrixDirect = directFired,
            matrixIndirect = indirectFired,
        )
    }
}
