package com.example.rat3.vpn

import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Minimal IPv4/IPv6 + TCP/UDP header parse/build helpers for [RatVpnService].
 *
 * IPv6 support is intentionally narrow: only the common case of a fixed 40-byte header
 * followed directly by a TCP or UDP segment is handled, matching what an ordinary
 * HTTP/HTTPS/QUIC session actually produces. A packet using IPv6 extension headers
 * (Hop-by-Hop Options, Routing, Fragment, ESP/AH, Destination Options before the transport
 * header) is not specially detected and will be misparsed the same way an unsupported
 * protocol is elsewhere in this file — dropped by the caller failing a follow-on parse,
 * not crashed on. This is a documented scope limit (extension headers are rare outside
 * specialized traffic), not a silent gap; unlike the IPv4 path, it has not been verified
 * against real IPv6 network traffic on a physical device.
 */
object IpPacket {
    const val PROTOCOL_TCP = 6
    const val PROTOCOL_UDP = 17
    private const val IPV6_HEADER_LEN = 40

    /** Common shape both IP versions parse into — everything [TcpRelay]/[UdpRelay] need,
     *  regardless of whether the addresses are 4 or 16 bytes long. */
    interface IpHeader {
        val protocol: Int
        val sourceAddress: ByteArray
        val destAddress: ByteArray
        val payloadOffset: Int
    }

    /** Parsed IPv4 header fields. [payloadOffset] is where the TCP/UDP header starts. */
    data class Ipv4Header(
        val version: Int,
        val ihl: Int,
        val totalLength: Int,
        override val protocol: Int,
        override val sourceAddress: ByteArray,
        override val destAddress: ByteArray,
        override val payloadOffset: Int,
    ) : IpHeader

    /** Parsed IPv6 fixed header fields (no extension headers — see class doc comment). */
    data class Ipv6Header(
        val payloadLength: Int,
        override val protocol: Int, // "next header" in IPv6 terms
        override val sourceAddress: ByteArray,
        override val destAddress: ByteArray,
        override val payloadOffset: Int,
    ) : IpHeader

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

    fun parseIpv6(buf: ByteBuffer, length: Int): Ipv6Header? {
        if (length < IPV6_HEADER_LEN) return null
        val b0 = buf.get(0).toInt() and 0xFF
        val version = b0 shr 4
        if (version != 6) return null
        val payloadLength = ((buf.get(4).toInt() and 0xFF) shl 8) or (buf.get(5).toInt() and 0xFF)
        val nextHeader = buf.get(6).toInt() and 0xFF
        val src = ByteArray(16)
        val dst = ByteArray(16)
        for (i in 0 until 16) {
            src[i] = buf.get(8 + i)
            dst[i] = buf.get(24 + i)
        }
        return Ipv6Header(payloadLength, nextHeader, src, dst, IPV6_HEADER_LEN)
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

    /** Builds a complete IPv4/IPv6+TCP packet with correct header + TCP checksums. IP version
     *  is inferred from `srcAddr.size` (4 = IPv4, 16 = IPv6) — the same length every source
     *  address already carries throughout this relay, so callers never need to say which. */
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
        val isV6 = srcAddr.size == 16
        val ipHeaderLen = if (isV6) IPV6_HEADER_LEN else 20
        val tcpHeaderLen = 20
        val totalLen = ipHeaderLen + tcpHeaderLen + payload.size
        val out = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(out)

        if (isV6) {
            writeIpv6Header(buf, srcAddr, dstAddr, PROTOCOL_TCP, tcpHeaderLen + payload.size)
        } else {
            writeIpv4Header(buf, out, srcAddr, dstAddr, PROTOCOL_TCP, totalLen)
        }

        // TCP header
        val tcpBase = ipHeaderLen
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

    /** Builds a complete IPv4/IPv6+UDP packet with correct header + UDP checksums. Version
     *  inferred from `srcAddr.size`, same as [buildTcpPacket]. IPv6 makes the UDP checksum
     *  mandatory (unlike IPv4, where 0 legally means "not computed") -- this relay always
     *  computes one anyway, but RFC 8200 §8.1 additionally requires substituting 0xFFFF for
     *  the ~1-in-65536 case where the computed checksum itself folds to 0x0000, since that
     *  wire value would otherwise be indistinguishable from "unchecked" and get the packet
     *  silently discarded by a spec-compliant receiver -- see the substitution below. */
    fun buildUdpPacket(
        srcAddr: ByteArray,
        dstAddr: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val isV6 = srcAddr.size == 16
        val ipHeaderLen = if (isV6) IPV6_HEADER_LEN else 20
        val udpLen = 8 + payload.size
        val totalLen = ipHeaderLen + udpLen
        val out = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(out)

        if (isV6) {
            writeIpv6Header(buf, srcAddr, dstAddr, PROTOCOL_UDP, udpLen)
        } else {
            writeIpv4Header(buf, out, srcAddr, dstAddr, PROTOCOL_UDP, totalLen)
        }

        val udpBase = ipHeaderLen
        putU16(buf, udpBase, srcPort)
        putU16(buf, udpBase + 2, dstPort)
        putU16(buf, udpBase + 4, udpLen)
        putU16(buf, udpBase + 6, 0)
        System.arraycopy(payload, 0, out, udpBase + 8, payload.size)

        var udpChecksum = tcpUdpChecksum(srcAddr, dstAddr, PROTOCOL_UDP, out, udpBase, udpLen)
        if (isV6 && udpChecksum == 0) udpChecksum = 0xFFFF // RFC 8200 §8.1: 0 is not valid over IPv6
        putU16(buf, udpBase + 6, udpChecksum)

        return out
    }

    // ── IP header writers ────────────────────────────────────────────────────────────────

    private fun writeIpv4Header(
        buf: ByteBuffer,
        out: ByteArray,
        srcAddr: ByteArray,
        dstAddr: ByteArray,
        protocol: Int,
        totalLen: Int,
    ) {
        buf.put(0, (0x45).toByte()) // version=4, IHL=5
        buf.put(1, 0) // DSCP/ECN
        putU16(buf, 2, totalLen)
        putU16(buf, 4, 0) // identification
        putU16(buf, 6, 0x4000) // flags: don't fragment
        buf.put(8, 64) // TTL
        buf.put(9, protocol.toByte())
        putU16(buf, 10, 0) // header checksum, filled below
        for (i in 0 until 4) buf.put(12 + i, srcAddr[i])
        for (i in 0 until 4) buf.put(16 + i, dstAddr[i])
        val ipChecksum = checksum(out, 0, 20)
        putU16(buf, 10, ipChecksum)
    }

    /** IPv6 has no header checksum at all (removed from the protocol) -- only the
     *  transport-level (TCP/UDP) checksum, via [tcpUdpChecksum]'s IPv6 pseudo-header. */
    private fun writeIpv6Header(
        buf: ByteBuffer,
        srcAddr: ByteArray,
        dstAddr: ByteArray,
        nextHeader: Int,
        payloadLength: Int,
    ) {
        buf.put(0, 0x60.toByte()) // version=6, traffic class high nibble=0
        buf.put(1, 0) // traffic class low nibble + flow label high nibble
        buf.put(2, 0) // flow label
        buf.put(3, 0)
        putU16(buf, 4, payloadLength)
        buf.put(6, nextHeader.toByte())
        buf.put(7, 64) // hop limit
        for (i in 0 until 16) buf.put(8 + i, srcAddr[i])
        for (i in 0 until 16) buf.put(24 + i, dstAddr[i])
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

    /** TCP/UDP checksum includes a pseudo-header: 12 bytes (src+dst+zero+protocol+length) for
     *  IPv4, or 40 bytes (src+dst+a wider 4-byte length+3 zero bytes+next-header) for IPv6 —
     *  inferred the same way as everywhere else here, from `srcAddr.size`. */
    private fun tcpUdpChecksum(
        srcAddr: ByteArray,
        dstAddr: ByteArray,
        protocol: Int,
        segment: ByteArray,
        segmentOffset: Int,
        segmentLength: Int,
    ): Int {
        val addrLen = srcAddr.size
        val isV6 = addrLen == 16
        val pseudoLen = if (isV6) 40 else 12
        val pseudoAndSegment = ByteArray(pseudoLen + segmentLength)
        System.arraycopy(srcAddr, 0, pseudoAndSegment, 0, addrLen)
        System.arraycopy(dstAddr, 0, pseudoAndSegment, addrLen, addrLen)
        if (isV6) {
            pseudoAndSegment[32] = ((segmentLength shr 24) and 0xFF).toByte()
            pseudoAndSegment[33] = ((segmentLength shr 16) and 0xFF).toByte()
            pseudoAndSegment[34] = ((segmentLength shr 8) and 0xFF).toByte()
            pseudoAndSegment[35] = (segmentLength and 0xFF).toByte()
            // bytes 36-38 are the mandatory zero padding; ByteArray already zero-initializes.
            pseudoAndSegment[39] = protocol.toByte()
        } else {
            pseudoAndSegment[8] = 0
            pseudoAndSegment[9] = protocol.toByte()
            pseudoAndSegment[10] = ((segmentLength shr 8) and 0xFF).toByte()
            pseudoAndSegment[11] = (segmentLength and 0xFF).toByte()
        }
        System.arraycopy(segment, segmentOffset, pseudoAndSegment, pseudoLen, segmentLength)
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

    /** [InetAddress.getByAddress] with a raw byte array never does a reverse-DNS lookup —
     *  it just formats the bytes -- so this is safe to call from a hot packet path for both
     *  IPv4 (dotted-decimal) and IPv6 (colon-hex) addresses, instead of hand-rolling IPv6's
     *  compressed notation separately. */
    fun addressToString(addr: ByteArray): String = try {
        InetAddress.getByAddress(addr).hostAddress ?: fallbackAddressToString(addr)
    } catch (_: Exception) {
        fallbackAddressToString(addr)
    }

    private fun fallbackAddressToString(addr: ByteArray): String =
        if (addr.size == 4) {
            addr.joinToString(".") { (it.toInt() and 0xFF).toString() }
        } else {
            addr.toList().chunked(2).joinToString(":") { pair ->
                pair.joinToString("") { "%02x".format(it) }
            }
        }
}
