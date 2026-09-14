package com.example.rat3.vpn

import android.net.VpnService
import android.util.Log
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.ArrayDeque
import kotlin.random.Random

/**
 * TCP side of [RatVpnService]'s NAT — the highest-risk piece of the VPN monitor (see the plan's
 * "Technical risk" note). RAT3 has to terminate the client's TCP connection at the tun interface
 * and re-originate it via a protected [SocketChannel] to the real destination, translating
 * sequence/ack numbers between the two sides, because there is no way to get real per-connection
 * visibility without acting as the actual endpoint.
 *
 * Deliberately simplified relative to a production TCP/IP stack (e.g. no retransmission timers,
 * no congestion window): the tun<->kernel path on-device is not a lossy link the way a real
 * network is, so a straightforward forward-everything-in-order relay is a reasonable trade-off
 * for a monitoring tool. This is NOT a general-purpose VPN client.
 */
class TcpRelay(
    private val vpnService: VpnService,
    private val selector: Selector,
    private val tracker: ConnectionTracker,
    private val writeToTun: (ByteArray) -> Unit,
) {
    private enum class State { SYN_RECEIVED, ESTABLISHED, CLOSING, CLOSED }

    private class Flow(
        val channel: SocketChannel,
        val clientAddr: ByteArray,
        val clientPort: Int,
        val destAddr: ByteArray,
        val destPort: Int,
    ) {
        var state = State.SYN_RECEIVED
        var ourSeq: Long = 0 // next sequence number WE will send
        var theirSeq: Long = 0 // next sequence number we EXPECT from the client (= our ack)
        val pendingWrites = ArrayDeque<ByteBuffer>()
        var lastActivityMs: Long = System.currentTimeMillis()
    }

    private val flows = HashMap<String, Flow>()

    private fun key(srcPort: Int, destAddr: ByteArray, destPort: Int) =
        "$srcPort:${IpPacket.addressToString(destAddr)}:$destPort"

    fun onPacket(ip: IpPacket.IpHeader, tcp: IpPacket.TcpHeader, buf: ByteBuffer, totalLength: Int) {
        val k = key(tcp.sourcePort, ip.destAddress, tcp.destPort)
        val payloadLen = totalLength - tcp.payloadOffset

        if (tcp.flagSyn && !tcp.flagAck) {
            openFlow(k, ip, tcp)
            return
        }

        flows[k]?.lastActivityMs = System.currentTimeMillis()
        val flow = flows[k] ?: run {
            // Unknown flow with no SYN on record (e.g. relay restarted mid-connection) -- RST it
            // so the client's TCP stack doesn't hang waiting for a reply that will never come.
            if (!tcp.flagRst) {
                sendRst(ip.sourceAddress, ip.destAddress, tcp.destPort, tcp.sourcePort, tcp.ack)
            }
            return
        }

        if (tcp.flagRst) {
            closeFlow(k)
            return
        }

        if (payloadLen > 0) {
            val payload = ByteArray(payloadLen)
            for (i in 0 until payloadLen) payload[i] = buf.get(tcp.payloadOffset + i)
            // The optimistic SYN-ACK (sent before the real destination connect() completes)
            // means client data -- e.g. a TLS ClientHello -- can arrive before flow.channel is
            // actually connected. Writing to a not-yet-connected SocketChannel throws
            // NotYetConnectedException, which used to be treated as a hard failure (RST) even
            // though the connection was fine; queue it instead and flush once connected.
            if (!flow.channel.isConnected) {
                flow.pendingWrites.add(ByteBuffer.wrap(payload))
            } else if (!writeNow(flow, ByteBuffer.wrap(payload), k)) {
                return
            }
            flow.theirSeq = tcp.seq + payloadLen
            sendAckOnly(flow)
            tracker.recordPacket(
                protocol = IpPacket.PROTOCOL_TCP,
                localAddress = IpPacket.addressToString(ip.sourceAddress),
                localPort = tcp.sourcePort,
                remoteAddress = IpPacket.addressToString(ip.destAddress),
                remotePort = tcp.destPort,
                bytesOut = payloadLen,
                bytesIn = 0,
            )
        }

        if (tcp.flagFin) {
            flow.theirSeq = tcp.seq + payloadLen + 1
            sendAckOnly(flow)
            if (flow.state == State.CLOSING) {
                // We'd already sent our own FIN (the real destination closed first) and this is
                // the client's half of a simultaneous close -- both sides are now done.
                closeFlow(k)
                return
            }
            try {
                flow.channel.shutdownOutput()
            } catch (_: Exception) {}
            flow.state = State.CLOSING
            sendFin(flow)
            return
        }

        if (tcp.flagAck && flow.state == State.SYN_RECEIVED) {
            flow.state = State.ESTABLISHED
        }
    }

    private fun openFlow(k: String, ip: IpPacket.IpHeader, tcp: IpPacket.TcpHeader) {
        val channel = try {
            SocketChannel.open().apply {
                vpnService.protect(socket())
                configureBlocking(false)
                connect(InetSocketAddress(IpPacket.addressToString(ip.destAddress), tcp.destPort))
            }
        } catch (e: Exception) {
            Log.w(TAG, "TCP connect setup failed for $k: ${e.message}")
            sendRst(ip.sourceAddress, ip.destAddress, tcp.destPort, tcp.sourcePort, tcp.ack)
            return
        }

        val flow = Flow(channel, ip.sourceAddress, tcp.sourcePort, ip.destAddress, tcp.destPort)
        flow.ourSeq = Random.nextLong(0, 0xFFFFFFFFL)
        flow.theirSeq = tcp.seq + 1 // SYN consumes one sequence number
        flows[k] = flow

        try {
            channel.register(selector, SelectionKey.OP_CONNECT, this to k)
        } catch (e: Exception) {
            Log.w(TAG, "TCP selector register failed for $k: ${e.message}")
            flows.remove(k)
            return
        }

        // Optimistic SYN-ACK: reply immediately so the client's TCP stack doesn't stall waiting
        // on the real (possibly slow) destination connect(). A failed connect sends RST after.
        writeToTun(
            IpPacket.buildTcpPacket(
                srcAddr = ip.destAddress,
                dstAddr = ip.sourceAddress,
                srcPort = tcp.destPort,
                dstPort = tcp.sourcePort,
                seq = flow.ourSeq,
                ack = flow.theirSeq,
                syn = true,
                ackFlag = true,
                fin = false,
                rst = false,
                psh = false,
                window = 65535,
                payload = ByteArray(0),
            ),
        )
        flow.ourSeq += 1
    }

    /** Called from the selector loop when a flow's real-destination channel connects, or has
     *  data to read. */
    fun onConnectable(k: String) {
        val flow = flows[k] ?: return
        try {
            if (flow.channel.finishConnect()) {
                flow.channel.register(selector, SelectionKey.OP_READ, this to k)
                // Flush anything the client sent while the real connect() was still pending
                // (see onPacket's isConnected check) -- in order, since pendingWrites is a FIFO
                // queue of already-parsed segments.
                while (flow.pendingWrites.isNotEmpty()) {
                    val buf = flow.pendingWrites.removeFirst()
                    if (!writeNow(flow, buf, k)) return
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "TCP connect failed for $k: ${e.message}")
            sendRst(flow.clientAddr, flow.destAddr, flow.destPort, flow.clientPort, flow.ourSeq)
            closeFlow(k)
        }
    }

    /** Writes to the real socket, tearing the flow down (RST to the client) on genuine failure.
     *  Returns false if the flow was closed as a result -- callers must stop touching `flow`. */
    private fun writeNow(flow: Flow, data: ByteBuffer, k: String): Boolean {
        return try {
            flow.channel.write(data)
            true
        } catch (e: Exception) {
            Log.w(TAG, "TCP write failed for $k: ${e.message}")
            sendRst(flow.clientAddr, flow.destAddr, flow.destPort, flow.clientPort, flow.ourSeq)
            closeFlow(k)
            false
        }
    }

    fun onReadable(k: String) {
        val flow = flows[k] ?: return
        flow.lastActivityMs = System.currentTimeMillis()
        val buf = ByteBuffer.allocate(MSS)
        val n = try {
            flow.channel.read(buf)
        } catch (e: Exception) {
            Log.w(TAG, "TCP read failed for $k: ${e.message}")
            sendRst(flow.clientAddr, flow.destAddr, flow.destPort, flow.clientPort, flow.ourSeq)
            closeFlow(k)
            return
        }
        if (n < 0) {
            // Real destination closed its side -- forward as FIN to the client.
            if (flow.state != State.CLOSING) {
                flow.state = State.CLOSING
                sendFin(flow)
            }
            return
        }
        if (n == 0) return
        buf.flip()
        val payload = ByteArray(n)
        buf.get(payload)

        writeToTun(
            IpPacket.buildTcpPacket(
                srcAddr = flow.destAddr,
                dstAddr = flow.clientAddr,
                srcPort = flow.destPort,
                dstPort = flow.clientPort,
                seq = flow.ourSeq,
                ack = flow.theirSeq,
                syn = false,
                ackFlag = true,
                fin = false,
                rst = false,
                psh = true,
                window = 65535,
                payload = payload,
            ),
        )
        flow.ourSeq += n

        tracker.recordPacket(
            protocol = IpPacket.PROTOCOL_TCP,
            localAddress = IpPacket.addressToString(flow.clientAddr),
            localPort = flow.clientPort,
            remoteAddress = IpPacket.addressToString(flow.destAddr),
            remotePort = flow.destPort,
            bytesOut = 0,
            bytesIn = n,
        )
    }

    private fun sendAckOnly(flow: Flow) {
        writeToTun(
            IpPacket.buildTcpPacket(
                srcAddr = flow.destAddr,
                dstAddr = flow.clientAddr,
                srcPort = flow.destPort,
                dstPort = flow.clientPort,
                seq = flow.ourSeq,
                ack = flow.theirSeq,
                syn = false,
                ackFlag = true,
                fin = false,
                rst = false,
                psh = false,
                window = 65535,
                payload = ByteArray(0),
            ),
        )
    }

    private fun sendFin(flow: Flow) {
        writeToTun(
            IpPacket.buildTcpPacket(
                srcAddr = flow.destAddr,
                dstAddr = flow.clientAddr,
                srcPort = flow.destPort,
                dstPort = flow.clientPort,
                seq = flow.ourSeq,
                ack = flow.theirSeq,
                syn = false,
                ackFlag = true,
                fin = true,
                rst = false,
                psh = false,
                window = 65535,
                payload = ByteArray(0),
            ),
        )
        flow.ourSeq += 1
    }

    private fun sendRst(
        clientAddr: ByteArray,
        destAddr: ByteArray,
        destPort: Int,
        clientPort: Int,
        seq: Long,
    ) {
        writeToTun(
            IpPacket.buildTcpPacket(
                srcAddr = destAddr,
                dstAddr = clientAddr,
                srcPort = destPort,
                dstPort = clientPort,
                seq = seq,
                ack = 0,
                syn = false,
                ackFlag = false,
                fin = false,
                rst = true,
                psh = false,
                window = 0,
                payload = ByteArray(0),
            ),
        )
    }

    private fun closeFlow(k: String) {
        val flow = flows.remove(k) ?: return
        try {
            flow.channel.close()
        } catch (_: Exception) {}
        tracker.markClosed(IpPacket.PROTOCOL_TCP, flow.clientPort, IpPacket.addressToString(flow.destAddr), flow.destPort)
    }

    fun closeAll() {
        flows.keys.toList().forEach { closeFlow(it) }
    }

    /** Closes flows that have gone quiet for too long. Catches sockets that should have been
     *  closed by a clean FIN/FIN-ACK exchange but weren't (this relay doesn't track the exact
     *  final ACK -- see the FIN handling in [onPacket]), so a normal request/response cycle
     *  doesn't leak a [SocketChannel] for the rest of the monitoring session. Call periodically,
     *  not per-packet. */
    fun reapStale(now: Long) {
        val idle = flows.entries.filter { now - it.value.lastActivityMs > IDLE_TIMEOUT_MS }
        idle.forEach { closeFlow(it.key) }
    }

    companion object {
        private const val TAG = "RAT3.TcpRelay"
        private const val MSS = 1400
        private const val IDLE_TIMEOUT_MS = 60_000L
    }
}
