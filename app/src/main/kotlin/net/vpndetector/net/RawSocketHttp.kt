package net.vpndetector.net

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.zip.GZIPInputStream
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class RawHttpResponse(
    val statusCode: Int?,
    val headers: Map<String, String>,
    val body: String,
)

data class TcpReachability(
    val port: Int? = null,
    val error: String? = null,
)

/**
 * Low-level HTTP over java.net.Socket / SSLSocket.
 *
 * This intentionally bypasses OkHttp so we can mirror apps that perform their
 * own raw-socket collectors. The goal here is transport parity, not a general
 * HTTP client implementation.
 */
object RawSocketHttp {

    fun get(
        url: String,
        timeoutMs: Int = 4_000,
        userAgent: String = "vpn-detector/max-parity",
    ): RawHttpResponse {
        val uri = URI(url)
        val host = uri.host ?: error("URL has no host: $url")
        val secure = (uri.scheme ?: "https").equals("https", ignoreCase = true)
        val port = when {
            uri.port != -1 -> uri.port
            secure -> 443
            else -> 80
        }
        val path = buildString {
            append(if (uri.rawPath.isNullOrEmpty()) "/" else uri.rawPath)
            if (!uri.rawQuery.isNullOrEmpty()) append('?').append(uri.rawQuery)
        }

        val request = buildString {
            append("GET $path HTTP/1.1\r\n")
            append("Host: $host\r\n")
            append("User-Agent: $userAgent\r\n")
            append("Accept: */*\r\n")
            append("Accept-Encoding: identity\r\n")
            append("Connection: close\r\n")
            append("\r\n")
        }.toByteArray(StandardCharsets.US_ASCII)

        val bytes = openSocket(host, port, secure, timeoutMs).use { socket ->
            val out = socket.getOutputStream()
            out.write(request)
            out.flush()
            val raw = ByteArrayOutputStream()
            socket.getInputStream().use { input ->
                val buf = ByteArray(8 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    raw.write(buf, 0, n)
                }
            }
            raw.toByteArray()
        }

        return parseResponse(bytes)
    }

    fun tcpReachable(
        host: String,
        ports: List<Int>,
        timeoutMs: Int = 2_500,
    ): TcpReachability {
        var lastError: String? = null
        for (port in ports) {
            val sock = Socket()
            try {
                sock.connect(InetSocketAddress(host, port), timeoutMs)
                return TcpReachability(port = port)
            } catch (e: Exception) {
                lastError = "tcp/$port: ${e.message ?: e.javaClass.simpleName}"
            } finally {
                try {
                    sock.close()
                } catch (_: Exception) {}
            }
        }
        return TcpReachability(error = lastError ?: "unreachable")
    }

    private fun openSocket(
        host: String,
        port: Int,
        secure: Boolean,
        timeoutMs: Int,
    ): Socket {
        val plain = Socket()
        plain.connect(InetSocketAddress(host, port), timeoutMs)
        plain.soTimeout = timeoutMs
        if (!secure) return plain

        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        val ssl = factory.createSocket(plain, host, port, true) as SSLSocket
        ssl.soTimeout = timeoutMs
        ssl.startHandshake()
        return ssl
    }

    private fun parseResponse(bytes: ByteArray): RawHttpResponse {
        val (headerEnd, separatorSize) = findHeaderEnd(bytes)
        if (headerEnd < 0) {
            return RawHttpResponse(
                statusCode = null,
                headers = emptyMap(),
                body = bytes.toString(Charsets.UTF_8),
            )
        }

        val headerText = String(bytes, 0, headerEnd, StandardCharsets.ISO_8859_1)
        val lines = headerText.split("\r\n", "\n").filter { it.isNotEmpty() }
        val statusCode = lines.firstOrNull()
            ?.split(' ')
            ?.getOrNull(1)
            ?.toIntOrNull()
        val headers = buildMap {
            for (line in lines.drop(1)) {
                val idx = line.indexOf(':')
                if (idx <= 0) continue
                put(
                    line.substring(0, idx).trim().lowercase(Locale.US),
                    line.substring(idx + 1).trim(),
                )
            }
        }

        var bodyBytes = bytes.copyOfRange(headerEnd + separatorSize, bytes.size)
        if (headers["transfer-encoding"]?.contains("chunked", ignoreCase = true) == true) {
            bodyBytes = decodeChunked(bodyBytes)
        } else {
            val declared = headers["content-length"]?.toIntOrNull()
            if (declared != null && bodyBytes.size > declared) {
                bodyBytes = bodyBytes.copyOf(declared)
            }
        }

        if (headers["content-encoding"]?.contains("gzip", ignoreCase = true) == true) {
            bodyBytes = runCatching {
                GZIPInputStream(ByteArrayInputStream(bodyBytes)).readBytes()
            }.getOrDefault(bodyBytes)
        }

        return RawHttpResponse(
            statusCode = statusCode,
            headers = headers,
            body = bodyBytes.toString(Charsets.UTF_8),
        )
    }

    private fun findHeaderEnd(bytes: ByteArray): Pair<Int, Int> {
        for (i in 0 until bytes.size - 3) {
            if (bytes[i] == '\r'.code.toByte() &&
                bytes[i + 1] == '\n'.code.toByte() &&
                bytes[i + 2] == '\r'.code.toByte() &&
                bytes[i + 3] == '\n'.code.toByte()
            ) {
                return i to 4
            }
        }
        for (i in 0 until bytes.size - 1) {
            if (bytes[i] == '\n'.code.toByte() && bytes[i + 1] == '\n'.code.toByte()) {
                return i to 2
            }
        }
        return -1 to 0
    }

    private fun decodeChunked(input: ByteArray): ByteArray {
        val stream = ByteArrayInputStream(input)
        val out = ByteArrayOutputStream()
        while (true) {
            val sizeLine = readAsciiLine(stream)?.trim().orEmpty()
            if (sizeLine.isEmpty()) continue
            val size = sizeLine.substringBefore(';').trim().toIntOrNull(16) ?: break
            if (size == 0) break
            out.write(readExactly(stream, size))
            skipLineBreak(stream)
        }
        return out.toByteArray()
    }

    private fun readAsciiLine(stream: ByteArrayInputStream): String? {
        val out = ByteArrayOutputStream()
        while (true) {
            val b = stream.read()
            if (b == -1) {
                return if (out.size() == 0) null else out.toString(StandardCharsets.ISO_8859_1.name())
            }
            if (b == '\n'.code) break
            if (b != '\r'.code) out.write(b)
        }
        return out.toString(StandardCharsets.ISO_8859_1.name())
    }

    private fun readExactly(stream: ByteArrayInputStream, size: Int): ByteArray {
        val out = ByteArray(size)
        var offset = 0
        while (offset < size) {
            val n = stream.read(out, offset, size - offset)
            if (n <= 0) break
            offset += n
        }
        return if (offset == size) out else out.copyOf(offset)
    }

    private fun skipLineBreak(stream: ByteArrayInputStream) {
        val first = stream.read()
        if (first == '\r'.code) {
            val second = stream.read()
            if (second != '\n'.code && second != -1) {
                // best-effort, nothing else to do here
            }
        }
    }
}
