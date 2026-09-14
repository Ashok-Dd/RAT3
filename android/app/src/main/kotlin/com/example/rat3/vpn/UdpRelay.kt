package com.example.rat3.vpn

import android.net.VpnService
import android.util.Log
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector

/**
 * UDP side of [RatVpnService]'s NAT: one real (protected) [DatagramChannel] per observed
 * (srcPort, dstAddress, dstPort) flow, relaying datagrams both ways. Low risk compared to
 * [TcpRelay] — UDP has no connection state to reconstruct, just forward-and-remember.
 */
class UdpRelay(
    private val vpnService: VpnService,
    private val selector: Selector,
    private val tracker: ConnectionTracker,
    private val writeToTun: (ByteArray) -> Unit,
) {
    private class Flow(
        val channel: DatagramChannel,
        val clientAddr: ByteArray,
        val clientPort: Int,
        val destAddr: ByteArray,
        val destPort: Int,
    ) {
        var lastActivityMs: Long = System.currentTimeMillis()
    }

    // Keyed by "clientPort:destAddr:destPort" -- one UDP "flow" per unique 3-tuple from our side.
    private val flows = HashMap<String, Flow>()

    fun onPacket(ip: IpPacket.IpHeader, udp: IpPacket.UdpHeader, buf: ByteBuffer, totalLength: Int) {
        val key = "${udp.sourcePort}:${IpPacket.addressToString(ip.destAddress)}:${udp.destPort}"
        val payloadLen = totalLength - udp.payloadOffset
        val payload = ByteArray(payloadLen)
        for (i in 0 until payloadLen) payload[i] = buf.get(udp.payloadOffset + i)

        val flow = flows.getOrPut(key) {
            val channel = DatagramChannel.open()
            vpnService.protect(channel.socket())
            channel.configureBlocking(false)
            channel.connect(InetSocketAddress(IpPacket.addressToString(ip.destAddress), udp.destPort))
            channel.register(selector, SelectionKey.OP_READ, this to key)
            Flow(channel, ip.sourceAddress, udp.sourcePort, ip.destAddress, udp.destPort)
        }

        flow.lastActivityMs = System.currentTimeMillis()
        try {
            flow.channel.write(ByteBuffer.wrap(payload))
        } catch (e: Exception) {
            Log.w(TAG, "UDP write failed for $key: ${e.message}")
            closeFlow(key)
            return
        }

        // Only the outbound query side is parsed -- the query's own question section is
        // enough to name what was being resolved, and it's simpler/safer than also parsing
        // (and trusting) a response payload from the real destination.
        val queriedDomain = if (udp.destPort == 53) DnsParser.extractQueryName(payload) else null

        tracker.recordPacket(
            protocol = IpPacket.PROTOCOL_UDP,
            localAddress = IpPacket.addressToString(ip.sourceAddress),
            localPort = udp.sourcePort,
            remoteAddress = IpPacket.addressToString(ip.destAddress),
            remotePort = udp.destPort,
            bytesOut = payloadLen,
            bytesIn = 0,
            queriedDomain = queriedDomain,
        )
    }

    /** Called from the selector loop when a flow's channel has data to read. */
    fun onReadable(key: String) {
        val flow = flows[key] ?: return
        flow.lastActivityMs = System.currentTimeMillis()
        val buf = ByteBuffer.allocate(32 * 1024)
        val n = try {
            flow.channel.read(buf)
        } catch (e: Exception) {
            Log.w(TAG, "UDP read failed for $key: ${e.message}")
            closeFlow(key)
            return
        }
        if (n <= 0) return
        buf.flip()
        val payload = ByteArray(n)
        buf.get(payload)

        val packet = IpPacket.buildUdpPacket(
            srcAddr = flow.destAddr,
            dstAddr = flow.clientAddr,
            srcPort = flow.destPort,
            dstPort = flow.clientPort,
            payload = payload,
        )
        writeToTun(packet)

        tracker.recordPacket(
            protocol = IpPacket.PROTOCOL_UDP,
            localAddress = IpPacket.addressToString(flow.clientAddr),
            localPort = flow.clientPort,
            remoteAddress = IpPacket.addressToString(flow.destAddr),
            remotePort = flow.destPort,
            bytesOut = 0,
            bytesIn = n,
        )
    }

    private fun closeFlow(key: String) {
        flows.remove(key)?.channel?.close()
    }

    fun closeAll() {
        flows.values.forEach { it.channel.close() }
        flows.clear()
    }

    /** Closes UDP flows that have gone quiet for too long. UDP has no "connection closed"
     *  signal at all, so without this every distinct (port, destination) pair a client ever
     *  used -- one per DNS query, one per QUIC connection, etc. -- would keep its
     *  DatagramChannel open for the rest of the monitoring session. Call periodically. */
    fun reapStale(now: Long) {
        val idle = flows.entries.filter { now - it.value.lastActivityMs > IDLE_TIMEOUT_MS }
        idle.forEach { closeFlow(it.key) }
    }

    companion object {
        private const val TAG = "RAT3.UdpRelay"
        private const val IDLE_TIMEOUT_MS = 30_000L
    }
}
