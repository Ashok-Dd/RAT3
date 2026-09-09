package com.example.rat3

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.hardware.camera2.CameraManager
import android.media.AudioManager
import android.net.TrafficStats
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.File

/**
 * ScanForegroundService — Persistent dual-trigger scanning (FIXED v2)
 *
 * ══════════════════════════════════════════════════════════════════════
 * ROOT CAUSE OF "SCANS ONLY ONCE AFTER SCREEN OFF" BUG — NOW FIXED
 * ══════════════════════════════════════════════════════════════════════
 *
 * OLD (broken) design:
 *   → Service runs scan → calls stopSelf() → service dies
 *   → AlarmManager fires 10 min later → tries to startForegroundService()
 *   → Android 12+ BLOCKS startForegroundService() from BroadcastReceiver
 *     when app is in background (Background Process Restrictions)
 *   → Service never starts → NO MORE SCANS
 *   → Result: exactly ONE scan after screen off, then silence
 *
 * NEW (fixed) design:
 *   → Service starts ONCE and NEVER calls stopSelf()
 *   → After each scan, re-arms TWO independent timers:
 *       Timer A: Handler.postDelayed(intervalMs) — for screen-on / active
 *       Timer B: AlarmManager.setExactAndAllowWhileIdle — for Doze / idle
 *   → Whichever fires first runs the scan; the other is cancelled
 *   → No startForegroundService() from background — service already running
 *
 * ══════════════════════════════════════════════════════════════════════
 *
 * LAYER 1 — Persistent Foreground Service
 *   startForeground() → protected process, survives swipe-away
 *   android:stopWithTask="false" in manifest → survives recents kill
 *   START_STICKY → restarts if OOM-killed (BootReceiver re-arms too)
 *   NEVER calls stopSelf() between scans
 *
 * LAYER 2 — Dual Timer: Handler + AlarmManager
 *   Handler.postDelayed() = fast path. Active when screen is on or
 *   the device is recently active. Frozen by Doze.
 *
 *   AlarmManager.setExactAndAllowWhileIdle() = Doze path. Wakes the
 *   CPU even during deep idle. Android 12+: checks canScheduleExactAlarms()
 *   at runtime; falls back to setWindow() if permission revoked.
 *
 *   Both are armed after every scan. The Handler fires first when screen
 *   is on (cancels the pending alarm). The alarm fires when Handler was
 *   frozen by Doze (alarm handler cancels pending Handler runnable).
 *
 * LAYER 3 — PARTIAL_WAKE_LOCK
 *   Alarm path: ScanAlarmReceiver acquires it BEFORE service receives intent
 *   Handler path: service acquires its own local WakeLock
 *   Both released in the finally block after scan completes
 *   3-minute timeout as absolute safety net
 *
 * BOOT RECOVERY:
 *   BootReceiver fires on BOOT_COMPLETED — Android wipes all alarms on reboot
 *   BootReceiver starts the service fresh → service re-arms both timers
 */
class ScanForegroundService : Service() {

    companion object {
        private const val TAG = "RAT-ScanService"

        const val NOTIF_ID_PERSISTENT = 101
        const val NOTIF_ID_ALERT_BASE = 200
        const val CHANNEL_MONITORING  = "rat_monitoring"
        const val CHANNEL_ALERTS      = "rat_alerts"

        const val EXTRA_INTERVAL_MS   = "scan_interval_ms"
        const val ACTION_STOP         = "com.example.rat3.STOP_SERVICE"
        const val ACTION_RUN_SCAN     = "com.example.rat3.RUN_SCAN"
        const val WAKELOCK_TAG        = "RatPrevention:ScanWakeLock"

        // Default changed to 10 minutes
        const val DEFAULT_INTERVAL_MS = 10 * 60 * 1000L
        private const val PREFS_NAME  = "rat_scan_prefs"
        const val KEY_INTERVAL        = "scan_interval_ms"

        // ── Static WakeLock bridges Receiver → Service gap ───────────────
        // BroadcastReceiver.onReceive() ends BEFORE Service.onStartCommand()
        // is called. Without this static field, the CPU can sleep in between,
        // causing a missed scan even if the alarm fires correctly.
        @Volatile
        var staticWakeLock: PowerManager.WakeLock? = null

        fun acquireStaticWakeLock(context: Context) {
            if (staticWakeLock?.isHeld == true) return
            val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            staticWakeLock = pm.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK, WAKELOCK_TAG
            ).apply { acquire(3 * 60 * 1000L) }
            Log.d(TAG, "Static WakeLock acquired")
        }

        fun releaseStaticWakeLock() {
            try {
                if (staticWakeLock?.isHeld == true) staticWakeLock?.release()
            } catch (_: Exception) {}
            staticWakeLock = null
            Log.d(TAG, "Static WakeLock released")
        }

        /**
         * Arms the Doze-safe alarm backup timer.
         *
         * Android 12+ REQUIRES canScheduleExactAlarms() check at runtime.
         * Without it, setExactAndAllowWhileIdle silently does nothing on
         * devices where SCHEDULE_EXACT_ALARM was revoked by the user.
         * Falls back to setWindow() which still fires in Doze but with
         * up to (intervalMs/2) of jitter — acceptable for our use case.
         */
        fun scheduleNextAlarm(context: Context, intervalMs: Long) {
            val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            val pi = PendingIntent.getBroadcast(
                context, 0,
                Intent(context, ScanAlarmReceiver::class.java).apply {
                    action = ACTION_RUN_SCAN
                },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val triggerAt = System.currentTimeMillis() + intervalMs

            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
                    // Android 12+ — MUST check permission before calling exact alarm API
                    if (am.canScheduleExactAlarms()) {
                        am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAt, pi)
                        Log.i(TAG, "Exact alarm armed: ${intervalMs/60000}min (Android 12+)")
                    } else {
                        // Permission revoked (user turned it off in Settings > Apps > Special access)
                        // setWindow still fires during Doze with some jitter — good enough
                        val window = (intervalMs * 0.3).toLong().coerceAtLeast(60_000L)
                        am.setWindow(AlarmManager.RTC_WAKEUP, triggerAt, window, pi)
                        Log.w(TAG, "canScheduleExactAlarms=false — setWindow fallback, window=${window/1000}s")
                    }
                }
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.M -> {
                    am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAt, pi)
                    Log.i(TAG, "Exact alarm armed: ${intervalMs/60000}min (Android 6-11)")
                }
                else -> {
                    am.setExact(AlarmManager.RTC_WAKEUP, triggerAt, pi)
                    Log.i(TAG, "Exact alarm armed: ${intervalMs/60000}min (pre-Android 6)")
                }
            }
        }

        fun cancelAlarm(context: Context) {
            val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            val pi = PendingIntent.getBroadcast(
                context, 0,
                Intent(context, ScanAlarmReceiver::class.java).apply {
                    action = ACTION_RUN_SCAN
                },
                PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE
            )
            pi?.let { am.cancel(it) }
            Log.d(TAG, "Alarm cancelled")
        }
    }

    private lateinit var scanThread: HandlerThread
    private lateinit var scanHandler: Handler
    private var scanIntervalMs = DEFAULT_INTERVAL_MS

    // Prevents two scan instances running concurrently if Handler and alarm
    // fire within milliseconds of each other
    @Volatile private var scanInProgress = false

    // ═════════════════════════════════════════════════════════════════════
    //  LIFECYCLE
    // ═════════════════════════════════════════════════════════════════════

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        scanThread = HandlerThread("RatScanThread").also { it.start() }
        scanHandler = Handler(scanThread.looper)
        Log.i(TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {

        // ── Stop action from notification "Stop Monitoring" button ────────
        if (intent?.action == ACTION_STOP) {
            Log.i(TAG, "Stop requested by user")
            cancelAlarm(this)
            scanHandler.removeCallbacksAndMessages(null)
            releaseStaticWakeLock()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
            stopSelf()
            return START_NOT_STICKY
        }

        // ── Recover / update interval ─────────────────────────────────────
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val incomingInterval = intent?.getLongExtra(EXTRA_INTERVAL_MS, -1L)
            ?.takeIf { it > 0 }
            ?: prefs.getLong(KEY_INTERVAL, DEFAULT_INTERVAL_MS)

        val intervalChanged = incomingInterval != scanIntervalMs
        scanIntervalMs = incomingInterval
        prefs.edit().putLong(KEY_INTERVAL, scanIntervalMs).apply()

        Log.i(TAG, "onStartCommand action=${intent?.action} interval=${scanIntervalMs/60000}min")

        // ── MUST call startForeground() within 5 seconds of onStartCommand ─
        // Android 14+ forbids starting some FGS types (incl. the old dataSync) from a
        // background trigger such as BOOT_COMPLETED. If that happens, fall back to a
        // plain background service + an AlarmManager alarm (the alarm broadcast, when
        // it fires, IS allowed to promote us to a foreground service).
        try {
            val notif = buildPersistentNotification(
                "Monitoring active — scanning every ${scanIntervalMs/60000}min",
            )
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(
                    NOTIF_ID_PERSISTENT,
                    notif,
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                )
            } else {
                startForeground(NOTIF_ID_PERSISTENT, notif)
            }
        } catch (e: Exception) {
            Log.w(TAG, "startForeground denied (${e.javaClass.simpleName}) — using alarm-only mode")
            scheduleNextAlarm(this, scanIntervalMs)
            stopSelf()
            return START_NOT_STICKY
        }

        // ── ACTION_RUN_SCAN from ScanAlarmReceiver (Doze wakeup path) ─────
        // The alarm fired because Doze froze our Handler.postDelayed().
        // The service is already running — we just need to trigger the scan.
        if (intent?.action == ACTION_RUN_SCAN) {
            Log.i(TAG, "Alarm wakeup received — triggering scan")
            // Cancel the Handler runnable (alarm beat it, avoid double scan)
            scanHandler.removeCallbacksAndMessages(null)
            triggerScan(wakeSource = "ALARM")
            return START_STICKY
        }

        // ── First start, boot recovery, or interval change ────────────────
        // Remove any pending Handler runnable so we don't get a stale scan
        // at the old interval, then start fresh
        if (intent == null || intent.action == null || intervalChanged) {
            scanHandler.removeCallbacksAndMessages(null)
            triggerScan(wakeSource = "START")
        }

        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        // Service was killed by OOM — START_STICKY will restart it
        // BootReceiver will also restart on next reboot
        super.onDestroy()
        scanHandler.removeCallbacksAndMessages(null)
        scanThread.quitSafely()
        releaseStaticWakeLock()
        Log.i(TAG, "Service destroyed (will restart via START_STICKY)")
    }

    // ═════════════════════════════════════════════════════════════════════
    //  CORE SCAN TRIGGER
    //
    //  Called from two paths:
    //    - Handler path (screen on / active): wakeSource = "HANDLER"
    //    - Alarm path  (Doze / screen off):   wakeSource = "ALARM"
    //    - First start / boot:                wakeSource = "START"
    //
    //  After every scan, re-arms BOTH timers so the next scan is covered
    //  regardless of whether the device enters or exits Doze.
    // ═════════════════════════════════════════════════════════════════════

    private fun triggerScan(wakeSource: String) {
        if (scanInProgress) {
            Log.d(TAG, "[$wakeSource] Scan already running — skip")
            // Still release any stale WakeLock from the alarm path
            releaseStaticWakeLock()
            return
        }

        // Handler path: acquire WakeLock ourselves (alarm path already holds one)
        val localWakeLock: PowerManager.WakeLock? = if (wakeSource != "ALARM") {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKELOCK_TAG).apply {
                acquire(3 * 60 * 1000L)
                Log.d(TAG, "[$wakeSource] Local WakeLock acquired")
            }
        } else null

        scanHandler.post {
            scanInProgress = true
            Log.i(TAG, "[$wakeSource] ▶ Scan started — interval=${scanIntervalMs/60000}min")

            try {
                runScan()
            } catch (e: Exception) {
                Log.e(TAG, "[$wakeSource] Scan error: ${e.message}", e)
            } finally {
                scanInProgress = false

                // ── Re-arm BOTH timers after every scan ───────────────────
                //
                // Timer A — AlarmManager (Doze backup)
                //   Arms immediately. Will fire in intervalMs if Handler
                //   is frozen by Doze. If Handler fires first, this alarm
                //   is cancelled before it triggers.
                scheduleNextAlarm(this@ScanForegroundService, scanIntervalMs)

                // Timer B — Handler.postDelayed (active/screen-on path)
                //   Arms immediately. Will fire in intervalMs if device
                //   is active. When it fires, it cancels the alarm and
                //   starts the next scan cycle.
                scanHandler.postDelayed({
                    Log.i(TAG, "[HANDLER] Timer fired — interval=${scanIntervalMs/60000}min")
                    // We're active (Handler wasn't frozen), so cancel the
                    // alarm backup — we'll re-arm both after this scan
                    cancelAlarm(this@ScanForegroundService)
                    triggerScan(wakeSource = "HANDLER")
                }, scanIntervalMs)

                // Release WakeLocks
                releaseStaticWakeLock()
                try {
                    if (localWakeLock?.isHeld == true) {
                        localWakeLock.release()
                        Log.d(TAG, "[$wakeSource] Local WakeLock released")
                    }
                } catch (_: Exception) {}

                Log.i(TAG, "[$wakeSource] ◀ Scan done. Both timers re-armed for ${scanIntervalMs/60000}min")
            }
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    //  CORE SCAN — pure Kotlin, zero Flutter dependency
    // ═════════════════════════════════════════════════════════════════════

    private fun runScan() {
        Log.i(TAG, "▶ Scan start")
        val findings = mutableListOf<Finding>()

        try {
            // 1 ── HARDWARE SENSORS ───────────────────────────────────────
            val micOn    = checkMicInUse()
            val cameraOn = checkCameraInUse()
            if (micOn)    findings += Finding("mic_active",    Sev.HIGH,
                "Microphone in use",
                "An app has your microphone open while the screen is off. " +
                "If you are not on a call, an app may be recording you.")
            if (cameraOn) findings += Finding("camera_active", Sev.HIGH,
                "Camera in use",
                "An app has your camera open while the screen is off. " +
                "This is very suspicious — check camera permissions.")

            // 2 ── ACTIVE UPLOADS ─────────────────────────────────────────
            val uploads = detectActiveUploads()

            // 3 ── SENSOR + UPLOAD CORRELATION (strongest RAT signal) ─────
            if ((micOn || cameraOn) && uploads.isNotEmpty()) {
                findings += Finding("sensor_net_corr", Sev.CRITICAL,
                    "⚠ RAT Behaviour Detected",
                    "${if (micOn) "Microphone" else "Camera"} is active AND " +
                    "${uploads.first().name} is uploading data simultaneously. " +
                    "This is a primary indicator of spyware/RAT activity.")
            } else {
                for (u in uploads) findings += Finding("upload_${u.pkg}",
                    if (u.mb > 10) Sev.CRITICAL else Sev.HIGH,
                    "Background upload: ${u.name}",
                    "${u.name} sent ${"%.1f".format(u.mb)} MB while your screen was off.")
            }

            // 4 ── SYSTEM SECURITY ────────────────────────────────────────
            if (checkIsRooted()) findings += Finding("root", Sev.CRITICAL,
                "Device is rooted",
                "Root access detected. Any app can access all your data " +
                "without permission dialogs on a rooted device.")

            if (Settings.Global.getInt(contentResolver,
                    Settings.Global.ADB_ENABLED, 0) == 1)
                findings += Finding("usb_debug", Sev.HIGH,
                    "USB debugging enabled",
                    "ADB is ON. A connected PC can fully control your device, " +
                    "install apps silently, and read all files.")

            // 5 ── SIDELOADED HIGH-RISK APPS ──────────────────────────────
            for (a in getSideloadedRiskyApps()) findings += Finding(
                "sideload_${a.pkg}", Sev.HIGH,
                "Suspicious app: ${a.name}",
                "${a.name} was not installed from Play Store and has ${a.reason}.")

            // 6 ── ACCESSIBILITY ABUSE ─────────────────────────────────────
            for (name in getAccessibilityAbusers()) findings += Finding(
                "accessibility_$name", Sev.HIGH,
                "Accessibility abuse: $name",
                "$name has Accessibility Service access — it can read your " +
                "screen, capture passwords, and simulate touches.")

        } catch (e: Exception) {
            Log.e(TAG, "Scan error: ${e.message}", e)
        }

        Log.i(TAG, "◀ Scan done — ${findings.size} finding(s)")

        if (findings.isEmpty()) {
            updatePersistentNotification("Last scan: ${timeStr()} — Clean ✓  (next: +${scanIntervalMs/60000}min)")
        } else {
            val criticals = findings.count { it.sev == Sev.CRITICAL }
            updatePersistentNotification(
                "⚠ ${findings.size} threat(s) — " +
                if (criticals > 0) "$criticals CRITICAL" else "${findings.size} HIGH")
            findings.forEach { showAlertNotification(it) }
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    //  SECURITY CHECK IMPLEMENTATIONS
    // ═════════════════════════════════════════════════════════════════════

    private fun checkMicInUse(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return try {
                val am = getSystemService(AUDIO_SERVICE) as AudioManager
                val cfgs = am.activeRecordingConfigurations
                val myUid = android.os.Process.myUid()
                if (Build.VERSION.SDK_INT >= 28) {
                    cfgs.any { cfg ->
                        try {
                            val uid = cfg.javaClass.getMethod("getClientUid")
                                .invoke(cfg) as? Int
                            uid != null && uid != myUid
                        } catch (_: Exception) { true }
                    }
                } else {
                    cfgs.isNotEmpty()
                }
            } catch (_: Exception) { checkMicViaProc() }
        }
        return checkMicViaProc()
    }

    private fun checkMicViaProc(): Boolean = try {
        File("/proc/asound").walkTopDown().any { f ->
            f.name == "status" && f.canRead() &&
            f.readText().contains("RUNNING", ignoreCase = true)
        }
    } catch (_: Exception) { false }

    private fun checkCameraInUse(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) return false
        return try {
            val cm = getSystemService(CAMERA_SERVICE) as? CameraManager ?: return false
            val unavailable = mutableSetOf<String>()
            val ht = HandlerThread("CamPoll").also { it.start() }
            val cb = object : CameraManager.AvailabilityCallback() {
                override fun onCameraUnavailable(id: String) { unavailable.add(id) }
            }
            cm.registerAvailabilityCallback(cb, Handler(ht.looper))
            Thread.sleep(400)
            cm.unregisterAvailabilityCallback(cb)
            ht.quitSafely()
            unavailable.isNotEmpty()
        } catch (_: Exception) { false }
    }

    private fun checkIsRooted(): Boolean {
        val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/data/local/su", "/data/local/bin/su",
            "/system/bin/.ext/.su", "/system/sd/xbin/su")
        if (suPaths.any { File(it).exists() }) return true
        if (Build.TAGS?.contains("test-keys") == true) return true
        try {
            val mount = Runtime.getRuntime().exec("mount")
                .inputStream.bufferedReader().readText()
            if (mount.contains("/system") && mount.contains(" rw,")) return true
        } catch (_: Exception) {}
        listOf("com.topjohnwu.magisk", "com.noshufou.android.su",
               "eu.chainfire.supersu", "com.koushikdutta.superuser",
               "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine").forEach {
            try { packageManager.getPackageInfo(it, 0); return true }
            catch (_: PackageManager.NameNotFoundException) {}
        }
        return false
    }

    private fun detectActiveUploads(): List<Upload> {
        val result = mutableListOf<Upload>()
        try {
            val pm   = packageManager
            val pkgs = pm.getInstalledPackages(0)

            val snap1 = pkgs.mapNotNull { p ->
                val uid = p.applicationInfo?.uid ?: return@mapNotNull null
                val tx  = TrafficStats.getUidTxBytes(uid)
                if (tx > 0) p.packageName to tx else null
            }.toMap()

            Thread.sleep(3_000)

            for (pkg in pkgs) {
                try {
                    val ai = pkg.applicationInfo ?: continue
                    if (pkg.packageName == packageName) continue
                    val sys = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    val upd = (ai.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    if (sys && !upd) continue

                    val tx2   = TrafficStats.getUidTxBytes(ai.uid)
                    val tx1   = snap1[pkg.packageName] ?: 0L
                    val delta = tx2 - tx1

                    if (delta > 500 * 1024) {
                        val name = try { pm.getApplicationLabel(ai).toString() }
                                   catch (_: Exception) { pkg.packageName }
                        result += Upload(pkg.packageName, name, delta / (1024.0 * 1024.0))
                    }
                } catch (_: Exception) {}
            }
        } catch (e: Exception) { Log.w(TAG, "detectUploads: ${e.message}") }
        return result
    }

    private fun getSideloadedRiskyApps(): List<RiskyApp> {
        val result = mutableListOf<RiskyApp>()
        val highRiskPerms = setOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.READ_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
        )
        try {
            val pm   = packageManager
            val flag = PackageManager.GET_PERMISSIONS
            val pkgs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flag.toLong()))
            else @Suppress("DEPRECATION") pm.getInstalledPackages(flag)

            for (pkg in pkgs) {
                try {
                    val ai = pkg.applicationInfo ?: continue
                    if (pkg.packageName == packageName) continue
                    val sys = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    val upd = (ai.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    if (sys && !upd) continue

                    val installer = try {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                            pm.getInstallSourceInfo(pkg.packageName).installingPackageName
                        else @Suppress("DEPRECATION")
                            pm.getInstallerPackageName(pkg.packageName)
                    } catch (_: Exception) { null }

                    val sideloaded = installer.isNullOrEmpty() ||
                        installer == "com.android.packageinstaller" ||
                        installer == "com.google.android.packageinstaller"
                    if (!sideloaded) continue

                    val perms  = pkg.requestedPermissions ?: continue
                    val pFlags = pkg.requestedPermissionsFlags ?: continue
                    val granted = perms.filterIndexed { i, p ->
                        p in highRiskPerms && i < pFlags.size &&
                        (pFlags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                    }
                    if (granted.size < 2) continue

                    val name = try { pm.getApplicationLabel(ai).toString() }
                               catch (_: Exception) { pkg.packageName }
                    result += RiskyApp(pkg.packageName, name,
                        "${granted.size} high-risk permissions: " +
                        granted.joinToString { it.substringAfterLast(".") })
                } catch (_: Exception) {}
            }
        } catch (e: Exception) { Log.w(TAG, "sideloadedApps: ${e.message}") }
        return result
    }

    private fun getAccessibilityAbusers(): List<String> {
        val result = mutableListOf<String>()
        try {
            val pm   = packageManager
            val flag = PackageManager.GET_PERMISSIONS
            val pkgs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flag.toLong()))
            else @Suppress("DEPRECATION") pm.getInstalledPackages(flag)

            for (pkg in pkgs) {
                try {
                    val ai = pkg.applicationInfo ?: continue
                    if (pkg.packageName == packageName) continue
                    val sys = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    val upd = (ai.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    if (sys && !upd) continue
                    val perms = pkg.requestedPermissions ?: continue
                    if ("android.permission.BIND_ACCESSIBILITY_SERVICE" in perms)
                        result += try { pm.getApplicationLabel(ai).toString() }
                                  catch (_: Exception) { pkg.packageName }
                } catch (_: Exception) {}
            }
        } catch (e: Exception) { Log.w(TAG, "accessibilityAbusers: ${e.message}") }
        return result
    }

    // ═════════════════════════════════════════════════════════════════════
    //  NOTIFICATIONS
    // ═════════════════════════════════════════════════════════════════════

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        NotificationChannel(CHANNEL_MONITORING, "RAT-Prevention Monitoring",
            NotificationManager.IMPORTANCE_LOW).apply {
            description = "Persistent monitoring status — silent"
            setShowBadge(false)
            nm.createNotificationChannel(this)
        }
        NotificationChannel(CHANNEL_ALERTS, "RAT-Prevention Threats",
            NotificationManager.IMPORTANCE_HIGH).apply {
            description = "Threat alerts from background scans"
            enableLights(true); lightColor = 0xFFFF3300.toInt()
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 400, 100, 400, 100, 400)
            nm.createNotificationChannel(this)
        }
    }

    private fun buildPersistentNotification(text: String): Notification {
        val openPi = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stopPi = PendingIntent.getService(this, 1,
            Intent(this, ScanForegroundService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL_MONITORING)
            .setContentTitle("🛡 RAT-Prevention Active")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true).setAutoCancel(false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openPi)
            .addAction(android.R.drawable.ic_delete, "Stop Monitoring", stopPi)
            .build()
    }

    private fun updatePersistentNotification(text: String) {
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
            .notify(NOTIF_ID_PERSISTENT, buildPersistentNotification(text))
    }

    private fun showAlertNotification(f: Finding) {
        val openPi = PendingIntent.getActivity(this, f.id.hashCode(),
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("open_alerts", true)
            }, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val n = NotificationCompat.Builder(this, CHANNEL_ALERTS)
            .setContentTitle("${f.sev.emoji} ${f.title}")
            .setContentText(f.message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(f.message))
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(if (f.sev == Sev.CRITICAL) NotificationCompat.PRIORITY_MAX
                         else NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true).setContentIntent(openPi).build()
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
            .notify(NOTIF_ID_ALERT_BASE + (f.id.hashCode() and 0x7FFFFFFF) % 100, n)
    }

    private fun timeStr(): String {
        val c = java.util.Calendar.getInstance()
        return "%02d:%02d".format(c.get(java.util.Calendar.HOUR_OF_DAY),
                                  c.get(java.util.Calendar.MINUTE))
    }

    private data class Finding(val id: String, val sev: Sev, val title: String, val message: String)
    private data class Upload(val pkg: String, val name: String, val mb: Double)
    private data class RiskyApp(val pkg: String, val name: String, val reason: String)
    private enum class Sev(val emoji: String) { CRITICAL("🔴"), HIGH("🟠") }
}