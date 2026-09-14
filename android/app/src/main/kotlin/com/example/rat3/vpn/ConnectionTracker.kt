package com.example.rat3.vpn

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Records every connection [RatVpnService] observes, resolving the owning app via
 * [ConnectivityManager.getConnectionOwnerUid] (API 29+ — exactly the API built for a VPN app to
 * answer "which app made this connection"). This is the real, non-root source of the
 * process/app-level network visibility the Network tab now shows, replacing the old
 * `/proc/net/tcp` read that Android blocks for third-party apps on API 29+.
 */
class ConnectionTracker(private val context: Context) {

    data class Connection(
        val key: String,
        val protocol: String, // "TCP" | "UDP"
        val packageName: String,
        val appName: String,
        val remoteAddress: String,
        val remotePort: Int,
        var firstSeenMs: Long,
        var lastSeenMs: Long,
        var bytesSent: Long = 0,
        var bytesReceived: Long = 0,
        var packetCount: Long = 0,
        var reconnectCount: Int = 0,
        // Explicitly set false only by markClosed (TCP FIN/RST). UDP has no "close" signal, and
        // even a closed TCP flow's record should stop reading as ACTIVE once it's actually old —
        // isActive at read time (see snapshot()) also folds in recency, so this field alone is
        // not the full story.
        var isActive: Boolean = true,
        // The domain a UDP:53 query on this exact flow was asking to resolve, if this flow IS a
        // DNS query (DnsParser extracted it from the outbound packet) -- null for every other
        // kind of connection, and for a DNS flow whose query didn't parse cleanly. This names
        // *this* query's own target, not the subsequent connection(s) the answer led to -- there
        // is no NAT-level correlation from a resolved IP back to the domain that resolved it.
        var queriedDomain: String? = null,
    )

    private val connections = ConcurrentHashMap<String, Connection>()
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val pm = context.packageManager

    /** Records/updates one observed flow. [localAddress]/[localPort] are this device's side of
     *  the connection exactly as seen in the intercepted IP packet — required to resolve the
     *  owning UID via getConnectionOwnerUid, which matches against the OS's real conntrack
     *  table entry for that tuple. */
    fun recordPacket(
        protocol: Int,
        localAddress: String,
        localPort: Int,
        remoteAddress: String,
        remotePort: Int,
        bytesOut: Int,
        bytesIn: Int,
        queriedDomain: String? = null,
    ) {
        val key = "$protocol:$localPort:$remoteAddress:$remotePort"
        val now = System.currentTimeMillis()
        val existing = connections[key]
        if (existing != null) {
            existing.lastSeenMs = now
            existing.bytesSent += bytesOut
            existing.bytesReceived += bytesIn
            existing.packetCount++
            existing.isActive = true
            if (queriedDomain != null) existing.queriedDomain = queriedDomain
            return
        }

        val (pkg, appName) = resolveOwner(protocol, localAddress, localPort, remoteAddress, remotePort)
        // A new flow to an endpoint we've talked to before (different local port each time) is
        // the "repeated / persistent communication" signal the spec asks for.
        val reconnect = connections.values.count {
            it.packageName == pkg && it.remoteAddress == remoteAddress && it.remotePort == remotePort
        }

        connections[key] = Connection(
            key = key,
            protocol = if (protocol == IpPacket.PROTOCOL_TCP) "TCP" else "UDP",
            packageName = pkg,
            appName = appName,
            remoteAddress = remoteAddress,
            remotePort = remotePort,
            firstSeenMs = now,
            lastSeenMs = now,
            bytesSent = bytesOut.toLong(),
            bytesReceived = bytesIn.toLong(),
            packetCount = 1,
            reconnectCount = reconnect,
            queriedDomain = queriedDomain,
        )
    }

    fun markClosed(protocol: Int, localPort: Int, remoteAddress: String, remotePort: Int) {
        connections["$protocol:$localPort:$remoteAddress:$remotePort"]?.isActive = false
    }

    /** Snapshot for the platform channel.
     *
     * UDP has no "connection closed" signal, and even TCP flows can go quiet without ever
     * reaching [markClosed] (a client that stops sending after the server's last byte, without a
     * clean FIN/RST round-trip). Treating `isActive` as a flag that's only ever set once meant a
     * connection touched once stayed "ACTIVE" forever, and the table only shrank on a 10-minute
     * delay — on a real device this reached 100+ entries within a couple of minutes of ordinary
     * browsing, well before anything aged out, visibly degrading the connection list's
     * performance. `isActive` here is instead a recency check computed at read time; old entries
     * are dropped from the table itself well before that.
     */
    fun snapshot(): List<Connection> {
        val now = System.currentTimeMillis()
        val pruneCutoff = now - PRUNE_AFTER_MS
        val stale = connections.values.filter { it.lastSeenMs < pruneCutoff }
        stale.forEach { connections.remove(it.key) }

        val activeCutoff = now - ACTIVE_WINDOW_MS
        return connections.values
            .onEach { it.isActive = it.isActive && it.lastSeenMs >= activeCutoff }
            .sortedByDescending { it.lastSeenMs }
    }

    companion object {
        private const val ACTIVE_WINDOW_MS = 20_000L
        private const val PRUNE_AFTER_MS = 2 * 60 * 1000L
    }

    fun clear() = connections.clear()

    private fun resolveOwner(
        protocol: Int,
        localAddress: String,
        localPort: Int,
        remoteAddress: String,
        remotePort: Int,
    ): Pair<String, String> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return "unknown" to "Unknown"
        return try {
            val local = InetSocketAddress(localAddress, localPort)
            val remote = InetSocketAddress(remoteAddress, remotePort)
            val uid = cm.getConnectionOwnerUid(protocol, local, remote)
            if (uid < 0) return "unknown" to "Unknown"
            val pkgs = pm.getPackagesForUid(uid)
            val pkg = pkgs?.firstOrNull() ?: return "unknown" to "Unknown"
            val label = try {
                pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
            } catch (_: PackageManager.NameNotFoundException) {
                pkg
            }
            pkg to label
        } catch (_: Exception) {
            "unknown" to "Unknown"
        }
    }
}
