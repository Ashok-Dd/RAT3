package com.example.rat3.vpn

/**
 * Extracts the queried domain name from a plain (non-DoH/DoT) DNS query's UDP payload —
 * the only realistic vantage point [RatVpnService] has for "what domain was this connection
 * actually for," since it relays raw packets, not resolved names.
 *
 * Deliberately narrow: only the question-section QNAME of an outbound *query* (not a
 * response) is parsed, with no support for name compression pointers — a query's own
 * question section is always the first name in the message, so a real client query never
 * legitimately contains one. Anything that doesn't cleanly fit this shape returns null
 * rather than guessing, matching [IpPacket]'s "drop, don't misparse" policy.
 */
object DnsParser {
    private const val MAX_LABELS = 32
    private const val MAX_LABEL_LENGTH = 63

    fun extractQueryName(payload: ByteArray): String? {
        if (payload.size < 12) return null

        // Header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)
        val flags0 = payload[2].toInt() and 0xFF
        val isResponse = (flags0 and 0x80) != 0 // QR bit
        if (isResponse) return null

        val qdCount = ((payload[4].toInt() and 0xFF) shl 8) or (payload[5].toInt() and 0xFF)
        if (qdCount < 1) return null

        val labels = mutableListOf<String>()
        var pos = 12
        while (pos < payload.size) {
            val len = payload[pos].toInt() and 0xFF
            if (len == 0) break // end of QNAME
            if (len and 0xC0 == 0xC0) return null // compression pointer -- not expected here
            if (len > MAX_LABEL_LENGTH) return null
            pos += 1
            if (pos + len > payload.size) return null
            // A real hostname label is printable ASCII (0x20-0x7E). Checked on the RAW bytes,
            // before decoding -- String(bytes, US_ASCII) silently replaces any unmappable byte
            // (0x80-0xFF) with '?' rather than failing, which would let binary garbage in a
            // malformed/adversarial label slip past a check made on the already-decoded string.
            for (i in pos until pos + len) {
                val b = payload[i].toInt() and 0xFF
                if (b < 0x20 || b > 0x7E) return null
            }
            val label = try {
                String(payload, pos, len, Charsets.US_ASCII)
            } catch (_: Exception) {
                return null
            }
            labels += label
            pos += len
            if (labels.size > MAX_LABELS) return null
        }

        if (labels.isEmpty()) return null
        return labels.joinToString(".")
    }
}
