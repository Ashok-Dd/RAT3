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
        var isActive: Boolean = true,
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
        )
    }

    fun markClosed(protocol: Int, localPort: Int, remoteAddress: String, remotePort: Int) {
        connections["$protocol:$localPort:$remoteAddress:$remotePort"]?.isActive = false
    }

    /** Snapshot for the platform channel. Drops entries not seen in the last 10 minutes so the
     *  table doesn't grow unbounded across a long monitoring session. */
    fun snapshot(): List<Connection> {
        val cutoff = System.currentTimeMillis() - 10 * 60 * 1000L
        val stale = connections.values.filter { !it.isActive && it.lastSeenMs < cutoff }
        stale.forEach { connections.remove(it.key) }
        return connections.values.sortedByDescending { it.lastSeenMs }
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
