package net.vpndetector.detect.consistency

import android.content.Context
import android.telephony.TelephonyManager
import net.vpndetector.AppStrings
import net.vpndetector.R
import net.vpndetector.detect.Category
import net.vpndetector.detect.Check
import net.vpndetector.detect.DetailEntry
import net.vpndetector.detect.Severity
import net.vpndetector.detect.geoip.GeoIpProbes
import net.vpndetector.detect.geoip.ProbeResult
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
        // For canonical v4 exit info, exclude the specialty probes that describe a different
        // egress (IPv6 exit, DNS resolver egress). They get their own dedicated checks below.
        val okV4 = ok.filter {
            it.provider !in GeoIpProbes.AGGREGATION_EXCLUDED && it.ip?.contains(":") != true
        }
        val ipCountry = okV4.firstNotNullOfOrNull { it.country }?.uppercase()
        val ipOrg = okV4.firstNotNullOfOrNull { it.org }
        val ipTz = okV4.firstNotNullOfOrNull { it.timezone }

        // simCountryIso / networkCountryIso / networkOperatorName / networkOperator do NOT
        // require READ_PHONE_STATE on any modern Android — keep these checks ungated.
        val tm = ctx.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager

        val unknown = AppStrings.get(R.string.val_unknown)

        // 1. SIM country vs IP country
        run {
            val sim = tm?.simCountryIso?.uppercase().orEmpty()
            val mismatch = sim.isNotEmpty() && ipCountry != null && sim != ipCountry
            out += Check(
                id = "sim_vs_ip",
                category = Category.CONSISTENCY,
                label = AppStrings.get(R.string.check_sim_vs_ip_label),
                value = AppStrings.get(R.string.val_sim_vs_ip, sim.ifEmpty { unknown }, ipCountry ?: unknown),
                severity = if (mismatch) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_sim_vs_ip_explanation),
            )
        }

        // 2. Network country vs IP
        run {
            val net = tm?.networkCountryIso?.uppercase().orEmpty()
            val mismatch = net.isNotEmpty() && ipCountry != null && net != ipCountry
            out += Check(
                id = "net_vs_ip",
                category = Category.CONSISTENCY,
                label = AppStrings.get(R.string.check_net_vs_ip_label),
                value = AppStrings.get(R.string.val_net_vs_ip, net.ifEmpty { unknown }, ipCountry ?: unknown),
                severity = if (mismatch) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_net_vs_ip_explanation),
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
                label = AppStrings.get(R.string.check_carrier_vs_asn_label),
                value = AppStrings.get(R.string.val_carrier_vs_asn, carrier.ifEmpty { unknown }, ipOrg ?: unknown),
                severity = if (mismatch) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_carrier_vs_asn_explanation),
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
                label = AppStrings.get(R.string.check_mcc_vs_ip_label),
                value = AppStrings.get(R.string.val_mcc_vs_ip, mcc.ifEmpty { unknown }, ipCountry ?: unknown),
                severity = if (mismatch) Severity.HARD else Severity.PASS,
                explanation = AppStrings.get(R.string.check_mcc_vs_ip_explanation),
            )
        }

        // 5. System locale country vs IP
        run {
            val lc = Locale.getDefault().country.uppercase()
            val mismatch = lc.isNotEmpty() && ipCountry != null && lc != ipCountry
            out += Check(
                id = "locale_vs_ip",
                category = Category.CONSISTENCY,
                label = AppStrings.get(R.string.check_locale_vs_ip_label),
                value = AppStrings.get(R.string.val_locale_vs_ip, lc, ipCountry ?: unknown),
                severity = if (mismatch) Severity.SOFT else Severity.PASS,
                explanation = AppStrings.get(R.string.check_locale_vs_ip_explanation),
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
                label = AppStrings.get(R.string.check_lang_vs_ip_label),
                value = AppStrings.get(R.string.val_lang_vs_ip, lang, ipCountry ?: unknown),
                severity = if (mismatch) Severity.SOFT else Severity.PASS,
                explanation = AppStrings.get(R.string.check_lang_vs_ip_explanation),
            )
        }

        // 7. Timezone id vs IP timezone
        run {
            val tz = TimeZone.getDefault().id
            val mismatch = ipTz != null && tz != ipTz
            out += Check(
                id = "tz_vs_ip",
                category = Category.CONSISTENCY,
                label = AppStrings.get(R.string.check_tz_vs_ip_label),
                value = AppStrings.get(R.string.val_tz_vs_ip, tz, ipTz ?: unknown),
                severity = when {
                    ipTz == null -> Severity.INFO
                    mismatch -> Severity.SOFT
                    else -> Severity.PASS
                },
                explanation = AppStrings.get(R.string.check_tz_vs_ip_explanation),
            )
        }

        // 8. Timezone offset vs IP offset (rough)
        run {
            val deviceOff = TimeZone.getDefault().rawOffset / 3_600_000
            out += Check(
                id = "tz_offset",
                category = Category.CONSISTENCY,
                label = AppStrings.get(R.string.check_tz_offset_label),
                value = if (deviceOff >= 0) AppStrings.get(R.string.val_tz_offset_plus, deviceOff)
                    else AppStrings.get(R.string.val_tz_offset_raw, deviceOff),
                severity = Severity.INFO,
                explanation = AppStrings.get(R.string.check_tz_offset_explanation),
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
                label = AppStrings.get(R.string.check_ru_apps_label),
                value = if (found.isEmpty()) AppStrings.get(R.string.val_none)
                    else AppStrings.get(R.string.val_ru_apps_summary, found.size, found.take(3).joinToString()),
                severity = if (mismatch) Severity.SOFT else Severity.INFO,
                explanation = AppStrings.get(R.string.check_ru_apps_explanation),
            )
        }

        // 10. IPv4 vs IPv6 exit split — the router-VPN signature.
        // Router-side VPNs almost always tunnel IPv4 only; IPv6 traffic from the phone bypasses
        // the tunnel and exits via the native ISP. If v4 is in a foreign datacenter and v6 is
        // a RU residential ISP (or vice versa), that's the tunnel type talking. Mismatch on
        // country OR ASN is HARD — anti-fraud SDKs that dual-stack-probe catch this directly.
        run {
            val v6Probe = ok.firstOrNull { it.provider == "ip-api-v6" }
            val v4Country = ipCountry
            val v4Org = ipOrg
            val v6Country = v6Probe?.country?.uppercase()
            val v6Org = v6Probe?.org
            val countryMismatch = v4Country != null && v6Country != null && v4Country != v6Country
            val orgMismatch = v4Org != null && v6Org != null &&
                !v4Org.equals(v6Org, ignoreCase = true) &&
                !v4Org.contains(v6Org, ignoreCase = true) &&
                !v6Org.contains(v4Org, ignoreCase = true)
            val haveBoth = v6Probe != null && v6Probe.error == null && v6Probe.ip != null && v4Country != null
            val sev = when {
                !haveBoth -> Severity.INFO
                countryMismatch -> Severity.HARD
                orgMismatch -> Severity.SOFT
                else -> Severity.PASS
            }
            val details = listOf(
                DetailEntry(
                    AppStrings.get(R.string.det_v4_exit),
                    AppStrings.get(R.string.val_v4_exit_line, v4Country ?: unknown, v4Org ?: unknown),
                    Severity.INFO,
                ),
                DetailEntry(
                    AppStrings.get(R.string.det_v6_exit),
                    when {
                        v6Probe == null -> AppStrings.get(R.string.val_no_v6_probe)
                        v6Probe.error != null -> AppStrings.get(R.string.val_error_prefix, v6Probe.error)
                        else -> AppStrings.get(R.string.val_v6_exit_line, v6Country ?: unknown, v6Org ?: unknown, v6Probe.ip ?: unknown)
                    },
                    if (countryMismatch) Severity.HARD else if (orgMismatch) Severity.SOFT else Severity.INFO,
                ),
            )
            out += Check(
                id = "v4_v6_exit_split",
                category = Category.CONSISTENCY,
                label = AppStrings.get(R.string.check_v4_v6_exit_split_label),
                value = when {
                    !haveBoth -> AppStrings.get(
                        R.string.val_v4_v6_info_line,
                        v4Country ?: unknown,
                        v6Probe?.error ?: v6Country ?: AppStrings.get(R.string.val_na),
                    )
                    countryMismatch -> AppStrings.get(R.string.val_country_split, v4Country ?: unknown, v6Country ?: unknown)
                    orgMismatch -> AppStrings.get(R.string.val_asn_split, v4Org ?: unknown, v6Org ?: unknown)
                    else -> AppStrings.get(R.string.val_aligned, v4Country ?: unknown, v4Org ?: unknown)
                },
                severity = sev,
                explanation = AppStrings.get(R.string.check_v4_v6_exit_split_explanation),
                details = details,
            )
        }

        // 11. DNS resolver egress vs HTTP exit.
        // `whoami.akamai.net` returns an A record equal to the recursive resolver's egress IP.
        // If that egress is in a different country than the HTTP exit the DNS path is not
        // traversing the same tunnel — classic DNS leak, or router DNS-interception routing
        // queries to an upstream outside the VPN.
        run {
            val resolver = ok.firstOrNull { it.provider == "resolver-egress" }
            val rCountry = resolver?.country?.uppercase()
            val rOrg = resolver?.org
            val countryMismatch = ipCountry != null && rCountry != null && ipCountry != rCountry
            val orgMismatch = ipOrg != null && rOrg != null &&
                !ipOrg.equals(rOrg, ignoreCase = true) &&
                !ipOrg.contains(rOrg, ignoreCase = true) &&
                !rOrg.contains(ipOrg, ignoreCase = true)
            val haveBoth = resolver != null && resolver.error == null && resolver.ip != null && ipCountry != null
            val sev = when {
                !haveBoth -> Severity.INFO
                countryMismatch -> Severity.HARD
                orgMismatch -> Severity.SOFT
                else -> Severity.PASS
            }
            val details = listOf(
                DetailEntry(
                    AppStrings.get(R.string.det_http_exit),
                    AppStrings.get(R.string.val_http_exit_line, ipCountry ?: unknown, ipOrg ?: unknown),
                    Severity.INFO,
                ),
                DetailEntry(
                    AppStrings.get(R.string.det_dns_resolver_egress),
                    when {
                        resolver == null -> AppStrings.get(R.string.val_no_probe)
                        resolver.error != null -> AppStrings.get(R.string.val_error_prefix, resolver.error)
                        else -> AppStrings.get(
                            R.string.val_dns_egress_line,
                            rCountry ?: unknown,
                            rOrg ?: unknown,
                            resolver.ip ?: unknown,
                        )
                    },
                    if (countryMismatch) Severity.HARD else if (orgMismatch) Severity.SOFT else Severity.INFO,
                ),
            )
            out += Check(
                id = "dns_vs_exit",
                category = Category.CONSISTENCY,
                label = AppStrings.get(R.string.check_dns_vs_exit_label),
                value = when {
                    !haveBoth -> AppStrings.get(
                        R.string.val_dns_exit_info_line,
                        ipCountry ?: unknown,
                        resolver?.error ?: rCountry ?: AppStrings.get(R.string.val_na),
                    )
                    countryMismatch -> AppStrings.get(R.string.val_country_leak, ipCountry ?: unknown, rCountry ?: unknown)
                    orgMismatch -> AppStrings.get(R.string.val_asn_leak, ipOrg ?: unknown, rOrg ?: unknown)
                    else -> AppStrings.get(R.string.val_aligned, ipCountry ?: unknown, ipOrg ?: unknown)
                },
                severity = sev,
                explanation = AppStrings.get(R.string.check_dns_vs_exit_explanation),
                details = details,
            )
        }

        return out
    }
}
