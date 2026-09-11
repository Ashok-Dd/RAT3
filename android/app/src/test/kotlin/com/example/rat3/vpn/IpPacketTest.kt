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
    fun `an IPv6 (or otherwise non-IPv4) buffer is rejected, not misparsed`() {
        val fakeIpv6 = ByteArray(40)
        fakeIpv6[0] = 0x60 // version nibble = 6
        val buf = ByteBuffer.wrap(fakeIpv6)
        assertEquals(null, IpPacket.parseIpv4(buf, fakeIpv6.size))
    }

    @Test
    fun `addressToString formats a dotted quad`() {
        assertEquals("10.233.0.2", IpPacket.addressToString(srcAddr))
    }
}
