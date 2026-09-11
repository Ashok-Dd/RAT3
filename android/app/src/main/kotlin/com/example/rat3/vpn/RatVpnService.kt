package com.example.rat3.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.rat3.MainActivity
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Optional, off-by-default (Settings toggle) local VPN used purely to see real per-connection
 * network activity — the Network tab's process/remote-IP/port/protocol view. Not a general VPN:
 * nothing is sent anywhere except the device's own real destinations, exactly as if this service
 * didn't exist; it just also records what it relays. See [TcpRelay]'s doc comment for the
 * biggest technical caveat (a simplified, non-production TCP relay).
 *
 * Requires the user's explicit system "Connection request" consent (`VpnService.prepare()`,
 * triggered from Settings) before Android will let this start.
 */
class RatVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var selector: Selector? = null
    private val running = AtomicBoolean(false)
    private var readerThread: Thread? = null
    private var selectorThread: Thread? = null
    private lateinit var tracker: ConnectionTracker
    private lateinit var tcpRelay: TcpRelay
    private lateinit var udpRelay: UdpRelay
    private val tunWriteLock = Any()
    private var tunOutput: FileOutputStream? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        tracker = ConnectionTracker(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (running.get()) return START_STICKY
        try {
            startForeground(NOTIF_ID, buildNotification())
            establishAndRun()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN monitor", e)
            stopSelf()
        }
        return START_STICKY
    }

    private fun establishAndRun() {
        val builder = Builder()
            .setSession("RAT3 Connection Monitor")
            .addAddress("10.233.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("8.8.4.4")
            .setMtu(MTU)
            // Never route our own traffic through the tun -- avoids a self-loop where RAT3's
            // own protected relay sockets would otherwise get captured and re-relayed.
            .addDisallowedApplication(packageName)

        vpnInterface = builder.establish() ?: run {
            Log.e(TAG, "VpnService.Builder.establish() returned null")
            stopSelf()
            return
        }

        selector = Selector.open()
        tunOutput = FileOutputStream(vpnInterface!!.fileDescriptor)
        tcpRelay = TcpRelay(this, selector!!, tracker, ::writeToTun)
        udpRelay = UdpRelay(this, selector!!, tracker, ::writeToTun)
        running.set(true)

        readerThread = Thread(::readLoop, "RatVpn-Reader").apply { start() }
        selectorThread = Thread(::selectorLoop, "RatVpn-Selector").apply { start() }
    }

    private fun writeToTun(packet: ByteArray) {
        try {
            synchronized(tunWriteLock) {
                tunOutput?.write(packet)
            }
        } catch (e: Exception) {
            Log.w(TAG, "writeToTun failed: ${e.message}")
        }
    }

    private fun readLoop() {
        val input = try {
            FileInputStream(vpnInterface!!.fileDescriptor)
        } catch (e: Exception) {
            Log.e(TAG, "Cannot open tun input stream", e)
            return
        }
        val raw = ByteArray(MTU + 64)
        while (running.get()) {
            val length = try {
                input.read(raw)
            } catch (e: Exception) {
                if (running.get()) Log.w(TAG, "tun read failed: ${e.message}")
                break
            }
            if (length <= 0) continue
            try {
                dispatch(raw, length)
            } catch (e: Exception) {
                Log.w(TAG, "dispatch failed: ${e.message}")
            }
        }
    }

    private fun dispatch(raw: ByteArray, length: Int) {
        val buf = ByteBuffer.wrap(raw, 0, length)
        val ip = IpPacket.parseIpv4(buf, length) ?: return // IPv6 or malformed -- skip, don't crash
        when (ip.protocol) {
            IpPacket.PROTOCOL_TCP -> {
                val tcp = IpPacket.parseTcp(buf, ip.payloadOffset, length) ?: return
                tcpRelay.onPacket(ip, tcp, buf, length)
            }
            IpPacket.PROTOCOL_UDP -> {
                val udp = IpPacket.parseUdp(buf, ip.payloadOffset, length) ?: return
                udpRelay.onPacket(ip, udp, buf, length)
            }
            else -> { /* ICMP etc. -- not relayed; monitoring doesn't need it */ }
        }
    }

    private fun selectorLoop() {
        val sel = selector ?: return
        while (running.get()) {
            val n = try {
                sel.select(1000)
            } catch (e: Exception) {
                if (running.get()) Log.w(TAG, "selector.select failed: ${e.message}")
                break
            }
            if (n == 0) continue
            val it = sel.selectedKeys().iterator()
            while (it.hasNext()) {
                val key = it.next()
                it.remove()
                try {
                    handleKey(key)
                } catch (e: Exception) {
                    Log.w(TAG, "handleKey failed: ${e.message}")
                }
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun handleKey(key: SelectionKey) {
        if (!key.isValid) return
        val (owner, flowKey) = key.attachment() as Pair<Any, String>
        when (owner) {
            is TcpRelay -> {
                if (key.isConnectable) owner.onConnectable(flowKey)
                if (key.isValid && key.isReadable) owner.onReadable(flowKey)
            }
            is UdpRelay -> {
                if (key.isReadable) owner.onReadable(flowKey)
            }
        }
    }

    fun connectionsSnapshot(): List<ConnectionTracker.Connection> =
        if (::tracker.isInitialized) tracker.snapshot() else emptyList()

    override fun onDestroy() {
        running.set(false)
        try { selector?.wakeup() } catch (_: Exception) {}
        readerThread?.interrupt()
        try {
            if (::tcpRelay.isInitialized) tcpRelay.closeAll()
            if (::udpRelay.isInitialized) udpRelay.closeAll()
        } catch (_: Exception) {}
        try { selector?.close() } catch (_: Exception) {}
        try { tunOutput?.close() } catch (_: Exception) {}
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        if (instance === this) instance = null
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val channelId = "rat_vpn_monitor"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(
                    channelId,
                    "RAT3 Connection Monitor",
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
        val openPi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopPi = PendingIntent.getService(
            this, 1,
            Intent(this, RatVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle("RAT3 Connection Monitor")
            .setContentText("Watching real-time network connections")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openPi)
            .addAction(android.R.drawable.ic_delete, "Stop", stopPi)
            .build()
    }

    companion object {
        private const val TAG = "RAT3.VpnService"
        private const val MTU = 32000
        private const val NOTIF_ID = 300
        const val ACTION_STOP = "com.example.rat3.vpn.STOP"

        @Volatile var instance: RatVpnService? = null
            private set

        fun isRunning(): Boolean = instance != null

        fun start(context: Context) {
            val intent = Intent(context, RatVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.startService(Intent(context, RatVpnService::class.java).apply { action = ACTION_STOP })
        }
    }
}
