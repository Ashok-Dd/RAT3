package com.example.rat3.vpn

import java.nio.ByteBuffer

/**
 * Minimal IPv4 + TCP/UDP header parse/build helpers for [RatVpnService].
 *
 * IPv6 is explicitly out of scope for this version — packets with a version nibble other than 4
 * are dropped by the caller, not silently misparsed. This is a deliberate, documented limitation
 * (see the VPN section of the plan / README), not an oversight.
 */
object IpPacket {
    const val PROTOCOL_TCP = 6
    const val PROTOCOL_UDP = 17

    /** Parsed IPv4 header fields. [payloadOffset] is where the TCP/UDP header starts. */
    data class Ipv4Header(
        val version: Int,
        val ihl: Int,
        val totalLength: Int,
        val protocol: Int,
        val sourceAddress: ByteArray,
        val destAddress: ByteArray,
        val payloadOffset: Int,
    )

    fun parseIpv4(buf: ByteBuffer, length: Int): Ipv4Header? {
        if (length < 20) return null
        val b0 = buf.get(0).toInt() and 0xFF
        val version = b0 shr 4
        if (version != 4) return null
        val ihl = (b0 and 0x0F) * 4
        if (ihl < 20 || length < ihl) return null
        val totalLength = ((buf.get(2).toInt() and 0xFF) shl 8) or (buf.get(3).toInt() and 0xFF)
        val protocol = buf.get(9).toInt() and 0xFF
        val src = ByteArray(4)
        val dst = ByteArray(4)
        for (i in 0 until 4) {
            src[i] = buf.get(12 + i)
            dst[i] = buf.get(16 + i)
        }
        return Ipv4Header(version, ihl, totalLength, protocol, src, dst, ihl)
    }

    data class TcpHeader(
        val sourcePort: Int,
        val destPort: Int,
        val seq: Long,
        val ack: Long,
        val dataOffset: Int,
        val flagSyn: Boolean,
        val flagAck: Boolean,
        val flagFin: Boolean,
        val flagRst: Boolean,
        val flagPsh: Boolean,
        val window: Int,
        val payloadOffset: Int,
    )

    fun parseTcp(buf: ByteBuffer, base: Int, length: Int): TcpHeader? {
        if (length - base < 20) return null
        val srcPort = u16(buf, base)
        val dstPort = u16(buf, base + 2)
        val seq = u32(buf, base + 4)
        val ack = u32(buf, base + 8)
        val offsetByte = buf.get(base + 12).toInt() and 0xFF
        val dataOffset = (offsetByte shr 4) * 4
        val flags = buf.get(base + 13).toInt() and 0xFF
        val window = u16(buf, base + 14)
        if (dataOffset < 20 || base + dataOffset > length) return null
        return TcpHeader(
            sourcePort = srcPort,
            destPort = dstPort,
            seq = seq,
            ack = ack,
            dataOffset = dataOffset,
            flagFin = flags and 0x01 != 0,
            flagSyn = flags and 0x02 != 0,
            flagRst = flags and 0x04 != 0,
            flagPsh = flags and 0x08 != 0,
            flagAck = flags and 0x10 != 0,
            window = window,
            payloadOffset = base + dataOffset,
        )
    }

    data class UdpHeader(
        val sourcePort: Int,
        val destPort: Int,
        val length: Int,
        val payloadOffset: Int,
    )

    fun parseUdp(buf: ByteBuffer, base: Int, totalLength: Int): UdpHeader? {
        if (totalLength - base < 8) return null
        return UdpHeader(
            sourcePort = u16(buf, base),
            destPort = u16(buf, base + 2),
            length = u16(buf, base + 4),
            payloadOffset = base + 8,
        )
    }

    // ── Packet building (for writing responses back into the tun) ──────────────────────────

    /** Builds a complete IPv4+TCP packet with correct header + TCP checksums. */
    fun buildTcpPacket(
        srcAddr: ByteArray,
        dstAddr: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        syn: Boolean,
        ackFlag: Boolean,
        fin: Boolean,
        rst: Boolean,
        psh: Boolean,
        window: Int,
        payload: ByteArray,
    ): ByteArray {
        val tcpHeaderLen = 20
        val totalLen = 20 + tcpHeaderLen + payload.size
        val out = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(out)

        // IPv4 header
        buf.put(0, (0x45).toByte()) // version=4, IHL=5
        buf.put(1, 0) // DSCP/ECN
        putU16(buf, 2, totalLen)
        putU16(buf, 4, 0) // identification
        putU16(buf, 6, 0x4000) // flags: don't fragment
        buf.put(8, 64) // TTL
        buf.put(9, PROTOCOL_TCP.toByte())
        putU16(buf, 10, 0) // header checksum, filled below
        for (i in 0 until 4) buf.put(12 + i, srcAddr[i])
        for (i in 0 until 4) buf.put(16 + i, dstAddr[i])
        val ipChecksum = checksum(out, 0, 20)
        putU16(buf, 10, ipChecksum)

        // TCP header
        val tcpBase = 20
        putU16(buf, tcpBase, srcPort)
        putU16(buf, tcpBase + 2, dstPort)
        putU32(buf, tcpBase + 4, seq)
        putU32(buf, tcpBase + 8, ack)
        buf.put(tcpBase + 12, ((tcpHeaderLen / 4) shl 4).toByte())
        var flags = 0
        if (fin) flags = flags or 0x01
        if (syn) flags = flags or 0x02
        if (rst) flags = flags or 0x04
        if (psh) flags = flags or 0x08
        if (ackFlag) flags = flags or 0x10
        buf.put(tcpBase + 13, flags.toByte())
        putU16(buf, tcpBase + 14, window)
        putU16(buf, tcpBase + 16, 0) // checksum, filled below
        putU16(buf, tcpBase + 18, 0) // urgent pointer
        System.arraycopy(payload, 0, out, tcpBase + tcpHeaderLen, payload.size)

        val tcpChecksum = tcpUdpChecksum(
            srcAddr, dstAddr, PROTOCOL_TCP, out, tcpBase, tcpHeaderLen + payload.size,
        )
        putU16(buf, tcpBase + 16, tcpChecksum)

        return out
    }

    /** Builds a complete IPv4+UDP packet with correct header + UDP checksums. */
    fun buildUdpPacket(
        srcAddr: ByteArray,
        dstAddr: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val out = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(out)

        buf.put(0, (0x45).toByte())
        buf.put(1, 0)
        putU16(buf, 2, totalLen)
        putU16(buf, 4, 0)
        putU16(buf, 6, 0x4000)
        buf.put(8, 64)
        buf.put(9, PROTOCOL_UDP.toByte())
        putU16(buf, 10, 0)
        for (i in 0 until 4) buf.put(12 + i, srcAddr[i])
        for (i in 0 until 4) buf.put(16 + i, dstAddr[i])
        val ipChecksum = checksum(out, 0, 20)
        putU16(buf, 10, ipChecksum)

        val udpBase = 20
        putU16(buf, udpBase, srcPort)
        putU16(buf, udpBase + 2, dstPort)
        putU16(buf, udpBase + 4, udpLen)
        putU16(buf, udpBase + 6, 0)
        System.arraycopy(payload, 0, out, udpBase + 8, payload.size)

        val udpChecksum = tcpUdpChecksum(srcAddr, dstAddr, PROTOCOL_UDP, out, udpBase, udpLen)
        putU16(buf, udpBase + 6, udpChecksum)

        return out
    }

    // ── Checksum helpers ─────────────────────────────────────────────────────────────────

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    /** TCP/UDP checksum includes a 12-byte IPv4 pseudo-header. */
    private fun tcpUdpChecksum(
        srcAddr: ByteArray,
        dstAddr: ByteArray,
        protocol: Int,
        segment: ByteArray,
        segmentOffset: Int,
        segmentLength: Int,
    ): Int {
        val pseudoAndSegment = ByteArray(12 + segmentLength)
        System.arraycopy(srcAddr, 0, pseudoAndSegment, 0, 4)
        System.arraycopy(dstAddr, 0, pseudoAndSegment, 4, 4)
        pseudoAndSegment[8] = 0
        pseudoAndSegment[9] = protocol.toByte()
        pseudoAndSegment[10] = ((segmentLength shr 8) and 0xFF).toByte()
        pseudoAndSegment[11] = (segmentLength and 0xFF).toByte()
        System.arraycopy(segment, segmentOffset, pseudoAndSegment, 12, segmentLength)
        return checksum(pseudoAndSegment, 0, pseudoAndSegment.size)
    }

    private fun u16(buf: ByteBuffer, offset: Int): Int =
        ((buf.get(offset).toInt() and 0xFF) shl 8) or (buf.get(offset + 1).toInt() and 0xFF)

    private fun u32(buf: ByteBuffer, offset: Int): Long {
        var v = 0L
        for (i in 0 until 4) v = (v shl 8) or (buf.get(offset + i).toLong() and 0xFF)
        return v
    }

    private fun putU16(buf: ByteBuffer, offset: Int, value: Int) {
        buf.put(offset, ((value shr 8) and 0xFF).toByte())
        buf.put(offset + 1, (value and 0xFF).toByte())
    }

    private fun putU32(buf: ByteBuffer, offset: Int, value: Long) {
        buf.put(offset, ((value shr 24) and 0xFF).toByte())
        buf.put(offset + 1, ((value shr 16) and 0xFF).toByte())
        buf.put(offset + 2, ((value shr 8) and 0xFF).toByte())
        buf.put(offset + 3, (value and 0xFF).toByte())
    }

    fun addressToString(addr: ByteArray): String =
        addr.joinToString(".") { (it.toInt() and 0xFF).toString() }
}
