package net.vpndetector.detect.consistency

import android.content.Context
import android.telephony.TelephonyManager
import net.vpndetector.detect.Category
import net.vpndetector.detect.Check
import net.vpndetector.detect.Severity
import net.vpndetector.detect.geoip.ProbeResult
import java.util.Locale
import java.util.TimeZone

/**
 * Cross-checks between local device context (SIM/locale/tz) and external GeoIP.
 * These are the decisive signals — a VPN changes the external IP but cannot change
 * the SIM country, MCC, carrier name, or system locale.
 */
object ConsistencyChecks {

    fun run(ctx: Context, probes: List<ProbeResult>): List<Check> {
        val out = mutableListOf<Check>()
        val ok = probes.filter { it.error == null }
        val ipCountry = ok.firstNotNullOfOrNull { it.country }?.uppercase()
        val ipOrg = ok.firstNotNullOfOrNull { it.org }
        val ipTz = ok.firstNotNullOfOrNull { it.timezone }

        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager

        // 1. SIM country vs IP country
        run {
            val sim = tm?.simCountryIso?.uppercase().orEmpty()
            val mismatch = sim.isNotEmpty() && ipCountry != null && sim != ipCountry
            out += Check(
                id = "sim_vs_ip",
                category = Category.CONSISTENCY,
                label = "SIM country vs IP country",
                value = "SIM=${sim.ifEmpty { "?" }} IP=${ipCountry ?: "?"}",
                severity = if (mismatch) Severity.HARD else Severity.PASS,
                explanation = "TelephonyManager.simCountryIso vs GeoIP. Mismatch = device is behind a VPN " +
                    "that exits in a different country than the SIM's home country.",
            )
        }

        // 2. Network country vs IP
        run {
            val net = tm?.networkCountryIso?.uppercase().orEmpty()
            val mismatch = net.isNotEmpty() && ipCountry != null && net != ipCountry
            out += Check(
                id = "net_vs_ip",
                category = Category.CONSISTENCY,
                label = "Network country vs IP country",
                value = "NET=${net.ifEmpty { "?" }} IP=${ipCountry ?: "?"}",
                severity = if (mismatch) Severity.HARD else Severity.PASS,
                explanation = "TelephonyManager.networkCountryIso (cell tower country) vs GeoIP.",
            )
        }

        // 3. Carrier name vs ASN org
        run {
            val carrier = tm?.networkOperatorName.orEmpty()
            val carrierLower = carrier.lowercase()
            val orgLower = ipOrg?.lowercase().orEmpty()
            // Simple heuristic: if carrier and org share no common words, they're likely different
            val carrierWords = carrierLower.split(" ", "-", "_").filter { it.length > 2 }
            val orgContainsCarrier = carrierWords.any { orgLower.contains(it) }
            val mismatch = carrier.isNotEmpty() && ipOrg != null && ipCountry != null &&
                !orgContainsCarrier && carrierLower != orgLower
            out += Check(
                id = "carrier_vs_asn",
                category = Category.CONSISTENCY,
                label = "Carrier vs ASN organisation",
                value = "carrier=${carrier.ifEmpty { "?" }} asn=${ipOrg ?: "?"}",
                severity = if (mismatch) Severity.SOFT else Severity.PASS,
                explanation = "Mobile operator name vs exit ASN. Different organisations suggest VPN routing.",
            )
        }

        // 4. MCC vs IP country
        run {
            val op = tm?.networkOperator.orEmpty()
            val mcc = if (op.length >= 3) op.substring(0, 3) else ""
            // ITU MCC → country mapping (simplified: first digit indicates region)
            // We only flag when we can definitively determine a mismatch
            val mccCountry = mccToCountry(mcc)
            val mismatch = mccCountry != null && ipCountry != null && mccCountry != ipCountry
            out += Check(
                id = "mcc_vs_ip",
                category = Category.CONSISTENCY,
                label = "MCC vs IP country",
                value = "MCC=${mcc.ifEmpty { "?" }}${mccCountry?.let { " ($it)" } ?: ""} IP=${ipCountry ?: "?"}",
                severity = if (mismatch) Severity.HARD else Severity.PASS,
                explanation = "Mobile Country Code mapped to ISO country vs GeoIP country.",
            )
        }

        // 5. System locale country vs IP
        run {
            val lc = Locale.getDefault().country.uppercase()
            val mismatch = lc.isNotEmpty() && ipCountry != null && lc != ipCountry
            out += Check(
                id = "locale_vs_ip",
                category = Category.CONSISTENCY,
                label = "Locale country vs IP",
                value = "locale=$lc IP=${ipCountry ?: "?"}",
                severity = if (mismatch) Severity.SOFT else Severity.PASS,
                explanation = "System locale region vs external country.",
            )
        }

        // 6. Timezone id vs IP timezone
        run {
            val tz = TimeZone.getDefault().id
            val mismatch = ipTz != null && tz != ipTz
            out += Check(
                id = "tz_vs_ip",
                category = Category.CONSISTENCY,
                label = "Timezone vs IP timezone",
                value = "device=$tz ip=${ipTz ?: "?"}",
                severity = when {
                    ipTz == null -> Severity.INFO
                    mismatch -> Severity.SOFT
                    else -> Severity.PASS
                },
                explanation = "TimeZone.getDefault() vs ipinfo timezone field.",
            )
        }

        // 7. Device UTC offset (diagnostic)
        run {
            val deviceOff = TimeZone.getDefault().rawOffset / 3_600_000
            out += Check(
                id = "tz_offset",
                category = Category.CONSISTENCY,
                label = "Device UTC offset",
                value = "${if (deviceOff >= 0) "+" else ""}$deviceOff",
                severity = Severity.INFO,
                explanation = "Diagnostic. Cross-check with ipinfo timezone in tz_vs_ip.",
            )
        }

        return out
    }

    /** Simplified MCC → ISO country mapping for common codes. */
    private fun mccToCountry(mcc: String): String? = when (mcc) {
        "250" -> "RU"
        "310", "311", "312", "313", "314", "315", "316" -> "US"
        "234", "235" -> "GB"
        "262" -> "DE"
        "208" -> "FR"
        "222" -> "IT"
        "214" -> "ES"
        "460" -> "CN"
        "440", "441" -> "JP"
        "450" -> "KR"
        "404", "405" -> "IN"
        "724" -> "BR"
        "515" -> "PH"
        "520" -> "TH"
        "510" -> "ID"
        "255" -> "UA"
        "257" -> "BY"
        "401" -> "KZ"
        else -> null
    }
}
