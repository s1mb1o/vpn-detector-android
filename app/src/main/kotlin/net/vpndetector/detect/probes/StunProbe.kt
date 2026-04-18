package net.vpndetector.detect.probes

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.vpndetector.detect.Category
import net.vpndetector.detect.Check
import net.vpndetector.detect.DetailEntry
import net.vpndetector.detect.Severity
import net.vpndetector.detect.geoip.GeoIpProbes
import net.vpndetector.detect.geoip.ProbeResult
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * STUN Binding Request (RFC 5389) — UDP-level reflexive address.
 *
 * WebRTC-capable apps (browsers, voice/video, messengers) fingerprint the device by asking a
 * STUN server for the mapped public address. When a VPN is at the router and only forwards
 * TCP/HTTP — or when an app-level VPN is configured with UDP bypass — the UDP STUN request
 * exits via the native ISP, revealing the pre-tunnel public IP. Fraud SDKs that run WebRTC in
 * a hidden iframe correlate this against the HTTP exit IP and flag mismatches.
 *
 * We mirror the same measurement: send a Binding Request to stun.l.google.com:19302, parse the
 * XOR-MAPPED-ADDRESS attribute from the response, and compare to the v4 HTTP exit seen by the
 * GeoIP probes. Mismatch = HARD (the VPN is not tunnelling UDP / not tunnelling all traffic).
 */
object StunProbe {

    private const val STUN_HOST = "stun.l.google.com"
    private const val STUN_PORT = 19302
    private const val MAGIC_COOKIE = 0x2112A442.toInt()
    private const val BINDING_REQUEST: Short = 0x0001
    private const val BINDING_SUCCESS = 0x0101
    private const val ATTR_XOR_MAPPED_ADDRESS = 0x0020
    private const val SO_TIMEOUT_MS = 2000

    suspend fun run(probes: List<ProbeResult>): List<Check> = withContext(Dispatchers.IO) {
        val httpExitV4 = probes.firstOrNull {
            it.error == null && it.ip != null && it.isIpv4 &&
                it.provider !in GeoIpProbes.AGGREGATION_EXCLUDED
        }?.ip
        val mapped = runCatching { stunBind() }.getOrNull()

        val (value, severity, explanationSuffix) = when {
            mapped == null ->
                Triple("no STUN response", Severity.INFO,
                    "UDP 19302 may be blocked upstream or blackholed — indeterminate, not scored.")
            httpExitV4 == null ->
                Triple("${mapped.first}:${mapped.second} (no HTTP v4 exit known)", Severity.INFO,
                    "We have no v4 HTTP exit to compare against.")
            mapped.first == httpExitV4 ->
                Triple("${mapped.first}:${mapped.second} (matches HTTP exit)", Severity.PASS,
                    "UDP and HTTP share the same public exit — no split-tunnel observable.")
            else ->
                Triple("${mapped.first} ≠ $httpExitV4  (UDP bypass)", Severity.HARD,
                    "UDP egress differs from HTTP egress — classic router-VPN / split-tunnel " +
                        "signature. WebRTC STUN reveals the native ISP IP while HTTP rides the tunnel.")
        }

        val details = buildList {
            add(DetailEntry("STUN server", "$STUN_HOST:$STUN_PORT", Severity.INFO))
            add(DetailEntry("XOR-MAPPED-ADDRESS",
                mapped?.let { "${it.first}:${it.second}" } ?: "(no response in ${SO_TIMEOUT_MS}ms)",
                Severity.INFO))
            add(DetailEntry("HTTP v4 exit (ipify/etc.)", httpExitV4 ?: "(unknown)", Severity.INFO))
        }

        listOf(
            Check(
                id = "stun_mapped_vs_exit",
                category = Category.PROBES,
                label = "STUN mapped address vs HTTP exit",
                value = value,
                severity = severity,
                explanation = "RFC 5389 Binding Request to stun.l.google.com:19302. Fraud SDKs run " +
                    "the equivalent via WebRTC in a hidden iframe and correlate the UDP mapped " +
                    "address with the HTTP exit. Router VPNs that only tunnel TCP — or VPNs " +
                    "configured to bypass UDP — produce a mismatch here that is not visible in " +
                    "any HTTP-based probe. $explanationSuffix",
                details = details,
            )
        )
    }

    /** Returns (ip, port) from XOR-MAPPED-ADDRESS, or null on any failure. */
    private fun stunBind(): Pair<String, Int>? {
        val addr = InetAddress.getByName(STUN_HOST)
        val txId = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val header = ByteBuffer.allocate(20).apply {
            putShort(BINDING_REQUEST)
            putShort(0)                         // message length: no attributes
            putInt(MAGIC_COOKIE)
            put(txId)
        }.array()

        DatagramSocket().use { sock ->
            sock.soTimeout = SO_TIMEOUT_MS
            sock.send(DatagramPacket(header, header.size, addr, STUN_PORT))

            val buf = ByteArray(1500)
            val resp = DatagramPacket(buf, buf.size)
            sock.receive(resp)
            return parseResponse(buf, resp.length, txId)
        }
    }

    private fun parseResponse(buf: ByteArray, len: Int, txId: ByteArray): Pair<String, Int>? {
        if (len < 20) return null
        val bb = ByteBuffer.wrap(buf, 0, len)
        val type = bb.short.toInt() and 0xffff
        if (type != BINDING_SUCCESS) return null
        val msgLen = bb.short.toInt() and 0xffff
        if (msgLen + 20 > len) return null
        if (bb.int != MAGIC_COOKIE) return null
        val respTx = ByteArray(12).also { bb.get(it) }
        if (!respTx.contentEquals(txId)) return null

        var remaining = msgLen
        while (remaining >= 4 && bb.remaining() >= 4) {
            val attrType = bb.short.toInt() and 0xffff
            val attrLen = bb.short.toInt() and 0xffff
            remaining -= 4
            if (bb.remaining() < attrLen) return null
            if (attrType == ATTR_XOR_MAPPED_ADDRESS) {
                return decodeXorMappedAddress(bb, attrLen, txId)
            }
            // Skip value + 4-byte padding.
            val pad = (4 - attrLen % 4) % 4
            bb.position(bb.position() + attrLen + pad)
            remaining -= attrLen + pad
        }
        return null
    }

    private fun decodeXorMappedAddress(bb: ByteBuffer, attrLen: Int, txId: ByteArray): Pair<String, Int>? {
        if (attrLen < 8) return null
        bb.get()                                         // reserved byte
        val family = bb.get().toInt() and 0xff
        val xport = (bb.short.toInt() and 0xffff) xor ((MAGIC_COOKIE ushr 16) and 0xffff)
        return when (family) {
            0x01 -> {
                if (attrLen < 8) return null
                val xip = bb.int xor MAGIC_COOKIE
                val ip = Inet4Address.getByAddress(ByteBuffer.allocate(4).putInt(xip).array())
                ip.hostAddress to xport
            }
            0x02 -> {
                if (attrLen < 20) return null
                val raw = ByteArray(16).also { bb.get(it) }
                val mask = ByteArray(16)
                mask[0] = 0x21; mask[1] = 0x12; mask[2] = 0xA4.toByte(); mask[3] = 0x42
                System.arraycopy(txId, 0, mask, 4, 12)
                val out = ByteArray(16) { i -> (raw[i].toInt() xor mask[i].toInt()).toByte() }
                val ip = Inet6Address.getByAddress(out)
                (ip.hostAddress ?: return null) to xport
            }
            else -> null
        }
    }
}
