package ru.shmelev.vpndetector.detect.consistency

import android.content.Context
import android.telephony.TelephonyManager
import ru.shmelev.vpndetector.detect.Category
import ru.shmelev.vpndetector.detect.Check
import ru.shmelev.vpndetector.detect.Severity
import ru.shmelev.vpndetector.detect.geoip.ProbeResult
import java.util.Locale
import java.util.TimeZone

/**
 * Cross-checks between local context (SIM/locale/tz) and external GeoIP. The decisive tab.
 */
object ConsistencyChecks {

    private val RU_CARRIERS = listOf(
        "mts", "beeline", "вымпел", "vimpel", "megafon", "мегафон", "tele2", "теле2",
        "yota", "ёта", "rostelecom", "ростелеком", "motiv", "tinkoff mobile",
    )

    fun run(ctx: Context, probes: List<ProbeResult>): List<Check> {
        val out = mutableListOf<Check>()
        val ok = probes.filter { it.error == null }
        val ipCountry = ok.firstNotNullOfOrNull { it.country }?.uppercase()
        val ipOrg = ok.firstNotNullOfOrNull { it.org }
        val ipTz = ok.firstNotNullOfOrNull { it.timezone }

        // simCountryIso / networkCountryIso / networkOperatorName / networkOperator do NOT
        // require READ_PHONE_STATE on any modern Android — keep these checks ungated.
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
                explanation = "TelephonyManager.simCountryIso vs GeoIP. The leak: SIM=RU, IP=US.",
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
            val isRuCarrier = RU_CARRIERS.any { carrier.contains(it, ignoreCase = true) }
            val orgIsRu = ipOrg?.let { o ->
                RU_CARRIERS.any { o.contains(it, ignoreCase = true) } ||
                    o.contains("rostelecom", true) || o.contains("er-telecom", true)
            } ?: false
            val mismatch = carrier.isNotEmpty() && isRuCarrier && !orgIsRu && ipCountry != null && ipCountry != "RU"
            out += Check(
                id = "carrier_vs_asn",
                category = Category.CONSISTENCY,
                label = "Carrier vs ASN organisation",
                value = "carrier=${carrier.ifEmpty { "?" }} asn=${ipOrg ?: "?"}",
                severity = if (mismatch) Severity.HARD else Severity.PASS,
                explanation = "RU mobile operator on SIM but exit ASN is foreign datacenter.",
            )
        }

        // 4. MCC (250 = RU) vs IP
        run {
            val op = tm?.networkOperator.orEmpty()
            val mcc = if (op.length >= 3) op.substring(0, 3) else ""
            val mismatch = mcc == "250" && ipCountry != null && ipCountry != "RU"
            out += Check(
                id = "mcc_vs_ip",
                category = Category.CONSISTENCY,
                label = "MCC vs IP country",
                value = "MCC=${mcc.ifEmpty { "?" }} IP=${ipCountry ?: "?"}",
                severity = if (mismatch) Severity.HARD else Severity.PASS,
                explanation = "MCC 250 = Russia. Mismatch with IP country = HARD.",
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

        // 6. Language vs IP country
        run {
            val lang = Locale.getDefault().language.lowercase()
            val cisCountries = setOf("RU", "BY", "KZ", "KG", "UA", "AM", "AZ", "TJ", "UZ", "MD", "TM")
            val mismatch = lang == "ru" && ipCountry != null && ipCountry !in cisCountries
            out += Check(
                id = "lang_vs_ip",
                category = Category.CONSISTENCY,
                label = "Language vs IP country",
                value = "lang=$lang IP=${ipCountry ?: "?"}",
                severity = if (mismatch) Severity.SOFT else Severity.PASS,
                explanation = "ru-language system but IP outside CIS.",
            )
        }

        // 7. Timezone id vs IP timezone
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

        // 8. Timezone offset vs IP offset (rough)
        run {
            val deviceOff = TimeZone.getDefault().rawOffset / 3_600_000
            // We don't have a numeric offset from probes; mark INFO unless we can compare via tz id
            out += Check(
                id = "tz_offset",
                category = Category.CONSISTENCY,
                label = "Device UTC offset",
                value = "${if (deviceOff >= 0) "+" else ""}$deviceOff",
                severity = Severity.INFO,
                explanation = "Diagnostic. Cross-check with ipinfo timezone in tz_vs_ip.",
            )
        }

        // 9. Installed RU apps presence (signal strength: many RU apps + non-RU IP)
        run {
            val markers = listOf(
                "ru.sberbank", "ru.sberbankmobile", "ru.yandex.searchplugin", "ru.yandex.mail",
                "ru.tinkoff.sirius", "com.idamob.tinkoff.android", "com.vkontakte.android",
                "ru.mail.cloud", "ru.gosuslugi", "ru.alfabank.mobile.android",
            )
            val pm = ctx.packageManager
            val found = markers.filter {
                runCatching { pm.getPackageInfo(it, 0); true }.getOrDefault(false)
            }
            val many = found.size >= 3
            val mismatch = many && ipCountry != null && ipCountry != "RU"
            out += Check(
                id = "ru_apps",
                category = Category.CONSISTENCY,
                label = "Russian apps installed",
                value = if (found.isEmpty()) "none" else "${found.size}: ${found.take(3).joinToString()}",
                severity = if (mismatch) Severity.SOFT else Severity.INFO,
                explanation = "Strong fingerprint: many Russian banking/social apps + non-RU IP.",
            )
        }

        return out
    }
}
