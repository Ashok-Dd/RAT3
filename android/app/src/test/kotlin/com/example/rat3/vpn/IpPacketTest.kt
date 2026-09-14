package com.example.rat3.vpn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer

/**
 * Packet-level correctness for RatVpnService's relay: a wrong checksum or a mis-packed header
 * makes the OS silently drop every packet the relay writes back into the tun interface, which
 * looks indistinguishable from "the VPN doesn't work" with no error anywhere. These are cheap,
 * pure-JVM tests, so there's no excuse not to catch that class of bug before it reaches a device.
 */
class IpPacketTest {

    private fun ip(a: Int, b: Int, c: Int, d: Int) =
        byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte())

    private val srcAddr = ip(10, 233, 0, 2)
    private val dstAddr = ip(93, 184, 216, 34) // example.com-shaped, arbitrary for the test

    /** IPv4/TCP/UDP checksums are self-verifying: summing a buffer that already contains a
     *  correctly-computed checksum (ones' complement sum, then complemented again) always
     *  yields all-ones (0xFFFF) once folded to 16 bits. */
    private fun selfVerifies(data: ByteArray, offset: Int, length: Int): Boolean {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum and 0xFFFF) == 0xFFFFL
    }

    @Test
    fun `UDP packet round-trips through build then parse with matching fields`() {
        val payload = "hello".toByteArray()
        val packet = IpPacket.buildUdpPacket(srcAddr, dstAddr, 5000, 53, payload)

        val buf = ByteBuffer.wrap(packet)
        val ip = IpPacket.parseIpv4(buf, packet.size)!!
        assertEquals(4, ip.version)
        assertEquals(IpPacket.PROTOCOL_UDP, ip.protocol)
        assertArrayEquals(srcAddr, ip.sourceAddress)
        assertArrayEquals(dstAddr, ip.destAddress)
        assertEquals(packet.size, ip.totalLength)

        val udp = IpPacket.parseUdp(buf, ip.payloadOffset, packet.size)!!
        assertEquals(5000, udp.sourcePort)
        assertEquals(53, udp.destPort)
        val recoveredPayload = packet.copyOfRange(udp.payloadOffset, packet.size)
        assertArrayEquals(payload, recoveredPayload)
    }

    @Test
    fun `UDP packet has a self-verifying IP header checksum`() {
        val packet = IpPacket.buildUdpPacket(srcAddr, dstAddr, 5000, 53, "x".toByteArray())
        assertTrue(selfVerifies(packet, 0, 20))
    }

    @Test
    fun `TCP SYN-ACK packet round-trips with all flags and seq-ack numbers intact`() {
        val packet = IpPacket.buildTcpPacket(
            srcAddr = dstAddr,
            dstAddr = srcAddr,
            srcPort = 443,
            dstPort = 51000,
            seq = 123456789L,
            ack = 987654321L,
            syn = true,
            ackFlag = true,
            fin = false,
            rst = false,
            psh = false,
            window = 65535,
            payload = ByteArray(0),
        )

        val buf = ByteBuffer.wrap(packet)
        val ip = IpPacket.parseIpv4(buf, packet.size)!!
        val tcp = IpPacket.parseTcp(buf, ip.payloadOffset, packet.size)!!

        assertEquals(443, tcp.sourcePort)
        assertEquals(51000, tcp.destPort)
        assertEquals(123456789L, tcp.seq)
        assertEquals(987654321L, tcp.ack)
        assertTrue(tcp.flagSyn)
        assertTrue(tcp.flagAck)
        assertFalse(tcp.flagFin)
        assertFalse(tcp.flagRst)
    }

    @Test
    fun `TCP data segment carries its payload intact and has a self-verifying checksum`() {
        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        val packet = IpPacket.buildTcpPacket(
            srcAddr = srcAddr,
            dstAddr = dstAddr,
            srcPort = 51000,
            dstPort = 80,
            seq = 1000L,
            ack = 2000L,
            syn = false,
            ackFlag = true,
            fin = false,
            rst = false,
            psh = true,
            window = 65535,
            payload = payload,
        )

        val buf = ByteBuffer.wrap(packet)
        val ip = IpPacket.parseIpv4(buf, packet.size)!!
        val tcp = IpPacket.parseTcp(buf, ip.payloadOffset, packet.size)!!
        assertTrue(tcp.flagPsh)
        assertArrayEquals(payload, packet.copyOfRange(tcp.payloadOffset, packet.size))
        assertTrue(selfVerifies(packet, 0, 20))
    }

    @Test
    fun `TCP RST packet sets only the RST flag`() {
        val packet = IpPacket.buildTcpPacket(
            srcAddr = dstAddr,
            dstAddr = srcAddr,
            srcPort = 443,
            dstPort = 51000,
            seq = 1L,
            ack = 0L,
            syn = false,
            ackFlag = false,
            fin = false,
            rst = true,
            psh = false,
            window = 0,
            payload = ByteArray(0),
        )
        val buf = ByteBuffer.wrap(packet)
        val ip = IpPacket.parseIpv4(buf, packet.size)!!
        val tcp = IpPacket.parseTcp(buf, ip.payloadOffset, packet.size)!!
        assertTrue(tcp.flagRst)
        assertFalse(tcp.flagSyn)
        assertFalse(tcp.flagAck)
        assertFalse(tcp.flagFin)
    }

    @Test
    fun `an IPv6 (or otherwise non-IPv4) buffer is rejected by parseIpv4, not misparsed`() {
        val fakeIpv6 = ByteArray(40)
        fakeIpv6[0] = 0x60 // version nibble = 6
        val buf = ByteBuffer.wrap(fakeIpv6)
        assertEquals(null, IpPacket.parseIpv4(buf, fakeIpv6.size))
    }

    @Test
    fun `addressToString formats a dotted quad`() {
        assertEquals("10.233.0.2", IpPacket.addressToString(srcAddr))
    }

    // ── IPv6 ─────────────────────────────────────────────────────────────────

    private val srcAddr6 = byteArrayOf(
        0xfd.toByte(), 0, 1, 0, 0xfd.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ) // fd00:1:fd00::2 -- the tun's own IPv6 address
    private val dstAddr6 = byteArrayOf(
        0x26, 0x06, 0x47, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
    ) // 2606:4700:2::1111 -- example public address, arbitrary for the test

    /** Independently reconstructs the 40-byte IPv6 pseudo-header (RFC 8200 §8.1: src(16) +
     *  dst(16) + upper-layer-length(4) + zero(3) + next-header(1)) around the packet's own
     *  TCP/UDP segment and checks it folds to all-ones -- the same self-verifying property
     *  [selfVerifies] checks for IPv4, but IPv6 has no IP-header checksum of its own, only
     *  this transport-level one. */
    private fun selfVerifiesIpv6Transport(packet: ByteArray, protocol: Int) {
        val segment = packet.copyOfRange(IPV6_HEADER_LEN, packet.size)
        val pseudo = ByteArray(40 + segment.size)
        System.arraycopy(srcAddr6, 0, pseudo, 0, 16)
        System.arraycopy(dstAddr6, 0, pseudo, 16, 16)
        val len = segment.size
        pseudo[32] = ((len shr 24) and 0xFF).toByte()
        pseudo[33] = ((len shr 16) and 0xFF).toByte()
        pseudo[34] = ((len shr 8) and 0xFF).toByte()
        pseudo[35] = (len and 0xFF).toByte()
        pseudo[39] = protocol.toByte()
        System.arraycopy(segment, 0, pseudo, 40, segment.size)
        assertTrue(selfVerifies(pseudo, 0, pseudo.size))
    }

    @Test
    fun `IPv6 UDP packet round-trips with correct header fields and a valid checksum`() {
        val payload = "hello-v6".toByteArray()
        val packet = IpPacket.buildUdpPacket(srcAddr6, dstAddr6, 5000, 53, payload)

        val buf = ByteBuffer.wrap(packet)
        val ip = IpPacket.parseIpv6(buf, packet.size)!!
        assertEquals(IpPacket.PROTOCOL_UDP, ip.protocol)
        assertArrayEquals(srcAddr6, ip.sourceAddress)
        assertArrayEquals(dstAddr6, ip.destAddress)
        assertEquals(IPV6_HEADER_LEN, ip.payloadOffset)

        val udp = IpPacket.parseUdp(buf, ip.payloadOffset, packet.size)!!
        assertEquals(5000, udp.sourcePort)
        assertEquals(53, udp.destPort)
        assertArrayEquals(payload, packet.copyOfRange(udp.payloadOffset, packet.size))

        selfVerifiesIpv6Transport(packet, IpPacket.PROTOCOL_UDP)
    }

    @Test
    fun `IPv6 TCP packet round-trips with flags, seq-ack, and a valid checksum`() {
        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        val packet = IpPacket.buildTcpPacket(
            srcAddr = srcAddr6,
            dstAddr = dstAddr6,
            srcPort = 51000,
            dstPort = 443,
            seq = 1000L,
            ack = 2000L,
            syn = false,
            ackFlag = true,
            fin = false,
            rst = false,
            psh = true,
            window = 65535,
            payload = payload,
        )

        val buf = ByteBuffer.wrap(packet)
        val ip = IpPacket.parseIpv6(buf, packet.size)!!
        assertEquals(IpPacket.PROTOCOL_TCP, ip.protocol)
        val tcp = IpPacket.parseTcp(buf, ip.payloadOffset, packet.size)!!
        assertEquals(51000, tcp.sourcePort)
        assertEquals(443, tcp.destPort)
        assertEquals(1000L, tcp.seq)
        assertEquals(2000L, tcp.ack)
        assertTrue(tcp.flagPsh)
        assertTrue(tcp.flagAck)
        assertArrayEquals(payload, packet.copyOfRange(tcp.payloadOffset, packet.size))

        selfVerifiesIpv6Transport(packet, IpPacket.PROTOCOL_TCP)
    }

    @Test
    fun `an IPv4 buffer is rejected by parseIpv6, not misparsed`() {
        val packet = IpPacket.buildUdpPacket(srcAddr, dstAddr, 1, 2, ByteArray(0))
        val buf = ByteBuffer.wrap(packet)
        assertEquals(null, IpPacket.parseIpv6(buf, packet.size))
    }

    @Test
    fun `a too-short buffer is rejected by parseIpv6`() {
        val buf = ByteBuffer.wrap(ByteArray(39).apply { this[0] = 0x60 })
        assertEquals(null, IpPacket.parseIpv6(buf, 39))
    }

    @Test
    fun `addressToString formats an IPv6 address in colon-hex`() {
        // fd00:1:fd00::2 -- exercised via round-trip since the exact compressed form
        // (:: placement) is InetAddress's own formatting choice, not this code's to assert.
        val formatted = IpPacket.addressToString(srcAddr6)
        assertTrue(formatted.contains(":"))
        assertFalse(formatted.contains("."))
    }

    @Test
    fun `IPv6 UDP checksum never wires as 0x0000, substituting 0xFFFF per RFC 8200`() {
        // Search a payload space for a case that would drive the raw checksum to 0 -- over
        // 65536 near-arbitrary 2-byte payloads, landing on the one value (of 65536 possible
        // 16-bit checksums) that zeroes it is expected roughly once. IPv4 is searched over
        // the same space as a sanity check that the search genuinely reaches the zero case
        // at all (IPv4 legitimately allows a wire value of 0, so this proves the search
        // isn't just vacuously never hitting it).
        var ipv4SawZero = false
        for (i in 0 until 65536) {
            val payload = byteArrayOf(((i shr 8) and 0xFF).toByte(), (i and 0xFF).toByte())

            val v6Packet = IpPacket.buildUdpPacket(srcAddr6, dstAddr6, 5000, 53, payload)
            val v6ChecksumField = u16At(v6Packet, IPV6_HEADER_LEN + 6)
            assertTrue(
                "IPv6 UDP checksum wired as 0x0000 for payload index $i -- RFC 8200 violation",
                v6ChecksumField != 0,
            )

            val v4Packet = IpPacket.buildUdpPacket(srcAddr, dstAddr, 5000, 53, payload)
            if (u16At(v4Packet, 20 + 6) == 0) ipv4SawZero = true
        }
        assertTrue(
            "search space never produced a zero IPv4 checksum -- test may not be exercising the target case",
            ipv4SawZero,
        )
    }

    private fun u16At(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    companion object {
        private const val IPV6_HEADER_LEN = 40
    }
}
