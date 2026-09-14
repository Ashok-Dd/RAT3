package com.example.rat3.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * DnsParser.extractQueryName runs on every UDP:53 packet the relay observes, including
 * ones from an untrusted/adversarial source (any app on the device). It must never throw,
 * and must never surface binary garbage as if it were a real domain name -- see the
 * class doc comment and CHANGELOG for the "checked raw bytes before decoding, not after"
 * fix this specifically guards.
 */
class DnsParserTest {

    /** Builds a minimal DNS query message: header + one question (QNAME + QTYPE=A + QCLASS=IN). */
    private fun buildQuery(labels: List<ByteArray>, isResponse: Boolean = false): ByteArray {
        val header = ByteArray(12)
        header[2] = if (isResponse) 0x80.toByte() else 0x00 // QR bit
        header[5] = 1 // QDCOUNT = 1

        val question = mutableListOf<Byte>()
        for (label in labels) {
            question += label.size.toByte()
            question += label.toList()
        }
        question += 0 // terminating zero-length label
        question += 0; question += 1 // QTYPE = A
        question += 0; question += 1 // QCLASS = IN

        return header + question.toByteArray()
    }

    private fun asciiLabel(s: String) = s.toByteArray(Charsets.US_ASCII)

    @Test
    fun `parses a simple two-label domain`() {
        val packet = buildQuery(listOf(asciiLabel("example"), asciiLabel("com")))
        assertEquals("example.com", DnsParser.extractQueryName(packet))
    }

    @Test
    fun `parses a multi-label subdomain`() {
        val packet = buildQuery(listOf(asciiLabel("api"), asciiLabel("whatsapp"), asciiLabel("com")))
        assertEquals("api.whatsapp.com", DnsParser.extractQueryName(packet))
    }

    @Test
    fun `returns null for a DNS response, not a query`() {
        val packet = buildQuery(listOf(asciiLabel("example"), asciiLabel("com")), isResponse = true)
        assertNull(DnsParser.extractQueryName(packet))
    }

    @Test
    fun `returns null for a buffer shorter than a DNS header`() {
        assertNull(DnsParser.extractQueryName(ByteArray(5)))
    }

    @Test
    fun `returns null for QDCOUNT of zero`() {
        val header = ByteArray(12) // QDCOUNT defaults to 0
        assertNull(DnsParser.extractQueryName(header))
    }

    @Test
    fun `returns null, does not throw, for a compression pointer in the question section`() {
        val header = ByteArray(12).apply { this[5] = 1 }
        val withPointer = header + byteArrayOf(0xC0.toByte(), 0x0C) // pointer, not a real label
        assertNull(DnsParser.extractQueryName(withPointer))
    }

    @Test
    fun `returns null, does not throw, for a label length that overruns the buffer`() {
        val header = ByteArray(12).apply { this[5] = 1 }
        val truncated = header + byteArrayOf(10, 'a'.code.toByte(), 'b'.code.toByte()) // claims 10, has 2
        assertNull(DnsParser.extractQueryName(truncated))
    }

    @Test
    fun `returns null, does not surface garbage, for a label containing raw binary bytes`() {
        // Regression test for the fix: String(bytes, US_ASCII) silently replaces unmappable
        // bytes (0x80-0xFF) with '?' instead of failing -- checking the DECODED string for
        // "is it printable ASCII" can no longer see the original bytes were binary. The
        // check must happen on the raw bytes before decoding.
        val header = ByteArray(12).apply { this[5] = 1 }
        val binaryLabel = byteArrayOf(4, 0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val packet = header + binaryLabel + byteArrayOf(0)
        assertNull(DnsParser.extractQueryName(packet))
    }

    @Test
    fun `returns null, does not throw, for a label containing control characters`() {
        val header = ByteArray(12).apply { this[5] = 1 }
        val controlLabel = byteArrayOf(3, 0x01, 0x02, 0x03)
        val packet = header + controlLabel + byteArrayOf(0)
        assertNull(DnsParser.extractQueryName(packet))
    }

    @Test
    fun `returns null for a label length exceeding the 63-byte DNS limit`() {
        val header = ByteArray(12).apply { this[5] = 1 }
        val packet = header + byteArrayOf(64) // length byte alone, no data needed to fail
        assertNull(DnsParser.extractQueryName(packet))
    }

    @Test
    fun `an entirely empty payload does not throw`() {
        assertNull(DnsParser.extractQueryName(ByteArray(0)))
    }
}
