package com.example.rat3

import android.app.ActivityManager
import android.app.AppOpsManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorManager
import android.net.TrafficStats
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.app.Activity
import android.content.ActivityNotFoundException
import android.net.Uri
import android.provider.OpenableColumns
import androidx.core.content.FileProvider
import com.example.rat3.scanner.ApkContext
import com.example.rat3.scanner.DecisionEngine
import com.example.rat3.scanner.Layer1SafetyAnalyzer
import com.example.rat3.scanner.Layer2PermissionMismatch
import com.example.rat3.scanner.Layer3SignatureScanner
import com.example.rat3.scanner.Layer4MlClassifier
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile
import java.util.zip.ZipFile

/**
 * The single Android entry point. Bridges Flutter to the native side over five channels:
 *
 *   MethodChannel  …/security  — the post-installation device monitor (~35 methods)
 *   MethodChannel  …/scanner   — pre-installation APK scan (scanApk)
 *   MethodChannel  …/file      — pickApkFile, getInitialApkPath  (+ pushes onIncomingApk)
 *   MethodChannel  …/install   — installApk
 *   EventChannel   …/progress  — pre-install scan layer progress
 */
class MainActivity : FlutterActivity() {

    companion object {
        private const val TAG = "RAT3"
        private const val CHANNEL = "com.example.rat3/security"

        private const val CH_SCANNER = "com.example.rat3/scanner"
        private const val CH_FILE = "com.example.rat3/file"
        private const val CH_INSTALL = "com.example.rat3/install"
        private const val CH_PROGRESS = "com.example.rat3/progress"
        private const val REQUEST_PICK_APK = 1001
        private const val APK_MIME = "application/vnd.android.package-archive"
        private const val CACHE_SUBDIR = "apk_scan"
    }

    // ── pre-install scanner state ───────────────────────────────────────────────────────
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var progressSink: EventChannel.EventSink? = null
    private var pendingFilePicker: MethodChannel.Result? = null
    private var fileChannel: MethodChannel? = null

    @Volatile
    private var pendingIntentPath: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleViewIntent(intent)
        Log.i(TAG, "MainActivity created")
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleViewIntent(intent)
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    @Deprecated("startActivityForResult kept for FlutterActivity compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_PICK_APK) return
        val pending = pendingFilePicker
        pendingFilePicker = null
        val uri = data?.data
        if (resultCode != Activity.RESULT_OK || uri == null) {
            pending?.success(null)
            return
        }
        scope.launch {
            val path = withContext(Dispatchers.IO) { resolveApkUri(uri) }
            pending?.success(path)
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val messenger = flutterEngine.dartExecutor.binaryMessenger

        // ── pre-install APK scanner channels ───────────────────────────────────────────
        MethodChannel(messenger, CH_SCANNER).setMethodCallHandler { call, result ->
            when (call.method) {
                "scanApk" -> {
                    val path = call.argument<String>("apkPath")
                    if (path.isNullOrBlank()) result.error("INVALID", "apkPath required", null)
                    else runScan(path, result)
                }
                else -> result.notImplemented()
            }
        }
        fileChannel = MethodChannel(messenger, CH_FILE).apply {
            setMethodCallHandler { call, result ->
                when (call.method) {
                    "pickApkFile" -> startApkPicker(result)
                    "getInitialApkPath" -> result.success(pendingIntentPath)
                    else -> result.notImplemented()
                }
            }
        }
        MethodChannel(messenger, CH_INSTALL).setMethodCallHandler { call, result ->
            when (call.method) {
                "installApk" -> {
                    val path = call.argument<String>("apkPath")
                    if (path.isNullOrBlank()) result.error("INVALID", "apkPath required", null)
                    else launchInstaller(path, result)
                }
                else -> result.notImplemented()
            }
        }
        EventChannel(messenger, CH_PROGRESS).setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) { progressSink = events }
            override fun onCancel(arguments: Any?) { progressSink = null }
        })
        pendingIntentPath?.let { notifyFlutterOfApk(it) }

        // ── post-install monitor channel ───────────────────────────────────────────────
        MethodChannel(messenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                Log.d(TAG, "MethodChannel: ${call.method}")
                when (call.method) {
                    "openUsageAccessSettings"            -> { openSettings(Settings.ACTION_USAGE_ACCESS_SETTINGS); result.success(null) }
                    "openAccessibilitySettings"          -> { openSettings(Settings.ACTION_ACCESSIBILITY_SETTINGS); result.success(null) }
                    "getCpuUsage"                         -> handleGetCpuUsage(result)
                    "getMemoryInfo"                       -> handleGetMemoryInfo(result)
                    "getNetworkConnections"               -> handleGetNetworkConnections(result)
                    "getNetworkDataUsage"                 -> handleGetNetworkDataUsage(result)
                    "getInstalledApps"                    -> handleGetInstalledApps(result)
                    "getRunningProcesses"                 -> handleGetRunningProcesses(result)
                    "getUsageStats"                       -> handleGetUsageStats(result)
                    "getGrantedPermissions"               -> handleGetGrantedPermissions(result)
                    "getBatteryInfo"                      -> handleGetBatteryInfo(result)
                    "isDeviceRooted"                      -> handleIsDeviceRooted(result)
                    "isDeveloperOptionsEnabled"           -> handleIsDeveloperOptionsEnabled(result)
                    "isUsbDebuggingEnabled"               -> handleIsUsbDebuggingEnabled(result)
                    "isIgnoringBatteryOptimizations"      -> handleIsIgnoringBatteryOptimizations(result)
                    "requestBatteryOptimizationExemption" -> handleRequestBatteryExemption(result)
                    "getSecurityFlags"                    -> handleGetSecurityFlags(result)
                    "scanAllApps"                         -> handleScanAllApps(result)
                    "getActiveSensors"                    -> handleGetActiveSensors(result)
                    "getAppPermissions"                   -> handleGetAppPermissions(call, result)
                    "getAppNetworkUsage"                  -> handleGetAppNetworkUsage(result)
                    "getUserInstalledSensorApps"          -> handleGetUserAppsUsingSensors(result)
                    "checkSensorInUse"                    -> handleCheckSensorInUse(result)
                    "getVpnStatus"                        -> handleGetVpnStatus(result)
                    "startForegroundService"              -> handleStartForegroundService(call, result)
                    "stopForegroundService"               -> handleStopForegroundService(result)
                    "getActiveAccessibilityServices"      -> handleGetActiveAccessibilityServices(result)
                    "isScreenRecordingActive"             -> handleIsScreenRecordingActive(result)
                    "getClipboardInfo"                    -> handleGetClipboardInfo(result)
                    "getDetailedSecurityFlags"            -> handleGetDetailedSecurityFlags(result)
                    else                                  -> result.notImplemented()
                }
            }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SCAN ALL APPS
    //  The most important new method. Returns a full audit of every
    //  installed non-system app including:
    //    • All permissions it requested
    //    • Whether dangerous permissions are granted
    //    • Its foreground/background usage time
    //    • Its install source (Play Store vs sideloaded)
    //    • Its target SDK (old SDK = higher risk)
    //    • Whether it was installed recently
    //    • Risk signals that classify it as SAFE / SUSPICIOUS / MALICIOUS
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleScanAllApps(result: MethodChannel.Result) {
        Thread {
            try {
                val pm = packageManager
                val flags = PackageManager.GET_PERMISSIONS or
                            PackageManager.GET_META_DATA

                val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstalledPackages(flags)
                }

                // Get usage stats for cross-referencing background activity
                val usageMap = getUsageStatsMap()

                // Get running process package names
                val am = getSystemService(ACTIVITY_SERVICE) as ActivityManager
                val runningPkgs = am.runningAppProcesses
                    ?.flatMap { it.pkgList?.toList() ?: emptyList<String>() }
                    ?.toSet() ?: emptySet()

                val results = mutableListOf<Map<String, Any?>>()

                for (pkg in packages) {
                    try {
                        val appInfo = pkg.applicationInfo ?: continue
                        val pkgNameCheck = pkg.packageName

                        // ── STRICT USER-APP FILTER ──────────────────────────
                        // Skip our own app entirely
                        if (pkgNameCheck == packageName) continue

                        // Skip ALL system apps — they are vetted by Android/OEM
                        val isSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                        val isUpdatedSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                        if (isSystem && !isUpdatedSystem) continue

                        // Skip known safe system package prefixes even if updated
                        val systemPrefixes = listOf(
                            "com.android.", "android.", "com.google.android.gms",
                            "com.google.android.gsf", "com.google.android.webview",
                            "com.google.android.networkstack", "com.google.android.captiveportallogin",
                            "com.google.android.permissioncontroller",
                        )
                        if (systemPrefixes.any { pkgNameCheck.startsWith(it) }) continue

                        val dangerousGranted = getDangerousGrantedPermissions(pkg)

                        val pkgName = pkgNameCheck
                        val appName = try {
                            pm.getApplicationLabel(appInfo).toString()
                        } catch (_: Exception) { pkgName }

                        // ── Install source ───────────────────────────────────
                        val installSource = getInstallSource(pkgName)
                        val isSideloaded  = installSource == "sideloaded"

                        // ── Age of install ───────────────────────────────────
                        val installDaysAgo = (System.currentTimeMillis() - pkg.firstInstallTime) /
                                (1000 * 60 * 60 * 24)
                        val isRecentInstall = installDaysAgo < 7

                        // ── All requested permissions ────────────────────────
                        val allPermissions = pkg.requestedPermissions?.toList() ?: emptyList<String>()

                        // ── Background time from UsageStats ─────────────────
                        val bgTimeMs = usageMap[pkgName] ?: 0L
                        val bgTimeHrs = bgTimeMs / 3600000.0

                        // ── Is currently running ─────────────────────────────
                        val isRunning = runningPkgs.contains(pkgName)

                        // ── Risk signal calculation ──────────────────────────
                        val riskSignals = mutableListOf<String>()
                        var riskScore   = 0

                        // Signal 1: Sideloaded app
                        if (isSideloaded) {
                            riskSignals.add("Sideloaded (not from Play Store)")
                            riskScore += 25
                        }

                        // Signal 2: Dangerous permissions granted
                        val highRiskPerms = listOf(
                            "android.permission.READ_CONTACTS",
                            "android.permission.READ_SMS",
                            "android.permission.RECORD_AUDIO",
                            "android.permission.CAMERA",
                            "android.permission.ACCESS_FINE_LOCATION",
                            "android.permission.ACCESS_BACKGROUND_LOCATION",
                            "android.permission.READ_CALL_LOG",
                            "android.permission.PROCESS_OUTGOING_CALLS",
                            "android.permission.BIND_ACCESSIBILITY_SERVICE",
                            "android.permission.BIND_DEVICE_ADMIN",
                            "android.permission.INSTALL_PACKAGES",
                            "android.permission.DELETE_PACKAGES",
                        )

                        val grantedHighRisk = dangerousGranted.filter { it in highRiskPerms }
                        if (grantedHighRisk.size >= 4) {
                            riskSignals.add("Holds ${grantedHighRisk.size} high-risk permissions")
                            riskScore += grantedHighRisk.size * 8
                        } else if (grantedHighRisk.size >= 2) {
                            riskSignals.add("${grantedHighRisk.size} sensitive permissions granted")
                            riskScore += grantedHighRisk.size * 5
                        }

                        // Signal 3: Accessibility service permission — very high risk
                        if ("android.permission.BIND_ACCESSIBILITY_SERVICE" in dangerousGranted ||
                            allPermissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")) {
                            riskSignals.add("Has Accessibility Service access (can read screen content)")
                            riskScore += 40
                        }

                        // Signal 4: Device admin permission
                        if (allPermissions.contains("android.permission.BIND_DEVICE_ADMIN")) {
                            riskSignals.add("Has Device Administrator privileges")
                            riskScore += 35
                        }

                        // Signal 5: Can install/delete packages (dropper behavior)
                        if (allPermissions.contains("android.permission.INSTALL_PACKAGES")) {
                            riskSignals.add("Can install other apps silently")
                            riskScore += 30
                        }

                        // Signal 6: Low target SDK (old/potentially unsafe code)
                        if (appInfo.targetSdkVersion < 26) {
                            riskSignals.add("Targets old Android API (${appInfo.targetSdkVersion}) — outdated security")
                            riskScore += 15
                        }

                        // Signal 7: Recent install
                        if (isRecentInstall) {
                            riskSignals.add("Installed $installDaysAgo day(s) ago")
                            riskScore += 10
                        }

                        // Signal 8: Excessive background time (> 4 hours/day)
                        if (bgTimeHrs > 4.0 && !isSystem) {
                            riskSignals.add("${String.format("%.1f", bgTimeHrs)}h background usage today")
                            riskScore += 15
                        }

                        // Signal 9: Background location (very invasive)
                        if ("android.permission.ACCESS_BACKGROUND_LOCATION" in dangerousGranted) {
                            riskSignals.add("Tracks location in background without user interaction")
                            riskScore += 30
                        }

                        // Signal 10: Read SMS (classic spyware signal)
                        if ("android.permission.READ_SMS" in dangerousGranted) {
                            riskSignals.add("Can read all your SMS messages")
                            riskScore += 25
                        }

                        // ── REAL-TIME ACTIVITY SIGNALS ───────────────────────
                        // These detect what your app IS DOING RIGHT NOW,
                        // not just what permissions it has.

                        // Signal 11: App is currently running in background
                        // (process exists but app is not foreground)
                        if (isRunning) {
                            val importance = am.runningAppProcesses
                                ?.firstOrNull { it.pkgList?.contains(pkgName) == true }
                                ?.importance ?: 0
                            // IMPORTANCE_BACKGROUND = 400, IMPORTANCE_SERVICE = 300
                            if (importance >= 300 && importance < 100.let { it }) {
                                riskSignals.add("Currently running in background (importance=$importance)")
                                riskScore += 12
                            } else if (importance > 0) {
                                riskSignals.add("Currently active process (importance=$importance)")
                                riskScore += 5
                            }
                        }

                        // Signal 12: Camera permission granted AND app is running
                        // → could be accessing camera silently
                        if ("android.permission.CAMERA" in dangerousGranted && isRunning) {
                            riskSignals.add("⚠ Has CAMERA access and is currently running")
                            riskScore += 20
                        }

                        // Signal 13: Microphone permission granted AND app is running
                        if ("android.permission.RECORD_AUDIO" in dangerousGranted && isRunning) {
                            riskSignals.add("⚠ Has MICROPHONE access and is currently running")
                            riskScore += 20
                        }

                        // Signal 14: Active network usage right now
                        // TrafficStats UID check — if app has TX bytes it sent data THIS session
                        val appUid = appInfo.uid
                        val appTxBytes = TrafficStats.getUidTxBytes(appUid)
                        val appRxBytes = TrafficStats.getUidRxBytes(appUid)
                        val hasActiveNetwork = appTxBytes > 0 || appRxBytes > 0
                        if (hasActiveNetwork) {
                            val txMB = appTxBytes / (1024.0 * 1024.0)
                            val rxMB = appRxBytes / (1024.0 * 1024.0)
                            if (appTxBytes > 1024 * 1024) { // > 1MB sent
                                riskSignals.add("Sent ${String.format("%.1f", txMB)}MB of data this session")
                                riskScore += if (appTxBytes > 10 * 1024 * 1024) 25 else 10
                            }
                            if (appRxBytes > 5 * 1024 * 1024) { // > 5MB received
                                riskSignals.add("Received ${String.format("%.1f", rxMB)}MB of data this session")
                            }
                        }

                        // ── Risk Classification ──────────────────────────────
                        val riskLevel = when {
                            riskScore >= 60 -> "MALICIOUS"
                            riskScore >= 30 -> "SUSPICIOUS"
                            else            -> "SAFE"
                        }

                        results.add(mapOf(
                            "packageName"        to pkgName,
                            "appName"            to appName,
                            "isSystemApp"        to isSystem,
                            "installSource"      to installSource,
                            "isSideloaded"       to isSideloaded,
                            "firstInstallTime"   to pkg.firstInstallTime,
                            "lastUpdateTime"     to pkg.lastUpdateTime,
                            "installDaysAgo"     to installDaysAgo,
                            "isRecentInstall"    to isRecentInstall,
                            "txBytes"            to (if (appTxBytes >= 0) appTxBytes else 0L),
                            "rxBytes"            to (if (appRxBytes >= 0) appRxBytes else 0L),
                            "isCurrentlyActive"  to isRunning,
                            "versionName"        to (pkg.versionName ?: "unknown"),
                            "targetSdkVersion"   to appInfo.targetSdkVersion,
                            "allPermissions"     to allPermissions,
                            "dangerousGranted"   to dangerousGranted,
                            "grantedHighRisk"    to grantedHighRisk,
                            "backgroundTimeMs"   to bgTimeMs,
                            "backgroundTimeHrs"  to bgTimeHrs,
                            "isCurrentlyRunning" to isRunning,
                            "riskScore"          to riskScore,
                            "riskLevel"          to riskLevel,
                            "riskSignals"        to riskSignals,
                        ))
                    } catch (e: Exception) {
                        Log.w(TAG, "scanAllApps: skip ${pkg.packageName}: ${e.message}")
                    }
                }

                // Sort: most dangerous first
                results.sortByDescending { (it["riskScore"] as? Int) ?: 0 }

                runOnUiThread { result.success(results) }
            } catch (e: Exception) {
                Log.e(TAG, "scanAllApps failed", e)
                runOnUiThread { result.error("SCAN_ERROR", e.message, null) }
            }
        }.start()
    }

    /** Returns list of DANGEROUS permissions that are actually GRANTED to the given package. */
    private fun getDangerousGrantedPermissions(pkg: PackageInfo): List<String> {
        val granted = mutableListOf<String>()
        val perms  = pkg.requestedPermissions ?: return granted
        val flags  = pkg.requestedPermissionsFlags ?: return granted

        for (i in perms.indices) {
            val isGranted = (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            if (isGranted) {
                try {
                    val info = packageManager.getPermissionInfo(perms[i], 0)
                    val protection = info.protectionLevel and android.content.pm.PermissionInfo.PROTECTION_MASK_BASE
                    if (protection == android.content.pm.PermissionInfo.PROTECTION_DANGEROUS) {
                        granted.add(perms[i])
                    }
                } catch (_: Exception) {}
            }
        }
        return granted
    }

    /** Returns install source: "play_store", "sideloaded", "system", "unknown" */
    private fun getInstallSource(pkgName: String): String {
        return try {
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                packageManager.getInstallSourceInfo(pkgName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                packageManager.getInstallerPackageName(pkgName)
            }
            when (installer) {
                "com.android.vending",
                "com.google.android.feedback" -> "play_store"
                null, ""                      -> "sideloaded"
                "com.android.packageinstaller",
                "com.google.android.packageinstaller" -> "sideloaded"
                else                          -> "other:$installer"
            }
        } catch (_: Exception) { "unknown" }
    }

    /** Returns usage stats map: packageName → totalTimeInForeground (ms) */
    private fun getUsageStatsMap(): Map<String, Long> {
        return try {
            if (!hasUsageStatsPermission()) return emptyMap()
            val usm   = getSystemService(USAGE_STATS_SERVICE) as UsageStatsManager
            val now   = System.currentTimeMillis()
            val start = now - 24 * 60 * 60 * 1000L
            val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, start, now)
            stats?.associate { it.packageName to it.totalTimeInForeground } ?: emptyMap()
        } catch (_: Exception) { emptyMap() }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  GET USER INSTALLED APPS WITH SENSOR PERMISSIONS
    //  Called by SensorScanScreen via getUserInstalledSensorApps().
    //  Returns every non-system user app with:
    //    • which sensor permissions (camera/mic/location) are GRANTED
    //    • whether it is currently running
    //    • background usage time today
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleGetUserAppsUsingSensors(result: MethodChannel.Result) {
        Thread {
            try {
                val pm  = applicationContext.packageManager
                val aom = getSystemService(APP_OPS_SERVICE) as AppOpsManager
                val nowMs = System.currentTimeMillis()

                // ══════════════════════════════════════════════════════════════
                //  STEP 1 — Find which apps are in foreground RIGHT NOW
                //
                //  UsageStatsManager.queryEvents() returns a stream of
                //  MOVE_TO_FOREGROUND / MOVE_TO_BACKGROUND events with exact
                //  timestamps. We query the last 60 seconds.
                //  If the most recent event for a package is MOVE_TO_FOREGROUND
                //  → that app is currently in foreground.
                //
                //  This is 100% public API, no @hide required.
                // ══════════════════════════════════════════════════════════════

                // packageName → most recent foreground start time (ms)
                val foregroundNow    = mutableSetOf<String>()  // currently in fg
                val foregroundRecent = mutableSetOf<String>()  // was in fg last 60s

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    try {
                        val usm = getSystemService(Context.USAGE_STATS_SERVICE)
                            as? UsageStatsManager
                        val events = usm?.queryEvents(nowMs - 60_000L, nowMs)
                        if (events != null) {
                            // Track the last event type per package
                            val lastEventType = mutableMapOf<String, Int>()
                            val lastEventTime = mutableMapOf<String, Long>()
                            val event = android.app.usage.UsageEvents.Event()
                            while (events.hasNextEvent()) {
                                events.getNextEvent(event)
                                lastEventType[event.packageName] = event.eventType
                                lastEventTime[event.packageName] = event.timeStamp
                            }
                            for ((pkg, evType) in lastEventType) {
                                val t = lastEventTime[pkg] ?: 0L
                                // MOVE_TO_FOREGROUND = 1
                                if (evType == android.app.usage.UsageEvents.Event.MOVE_TO_FOREGROUND) {
                                    foregroundNow.add(pkg)
                                    foregroundRecent.add(pkg)
                                } else if (evType == android.app.usage.UsageEvents.Event.MOVE_TO_BACKGROUND) {
                                    // Was in fg recently but just went to background
                                    if ((nowMs - t) < 60_000L) foregroundRecent.add(pkg)
                                }
                            }
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "UsageEvents query failed: ${e.message}")
                    }
                }

                Log.d(TAG, "Foreground NOW: $foregroundNow")
                Log.d(TAG, "Foreground RECENT: $foregroundRecent")

                // ══════════════════════════════════════════════════════════════
                //  STEP 2 — Get installed packages
                // ══════════════════════════════════════════════════════════════

                val flags = PackageManager.GET_PERMISSIONS
                val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstalledPackages(flags)
                }

                Log.d(TAG, "getUserAppsUsingSensors: raw package count = ${packages.size}")

                val usageMap = getUsageStatsMap()

                val sensorPermissions = setOf(
                    "android.permission.CAMERA",
                    "android.permission.RECORD_AUDIO",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.ACCESS_COARSE_LOCATION",
                    "android.permission.ACCESS_BACKGROUND_LOCATION",
                )

                val list = ArrayList<Map<String, Any>>()

                for (pkg in packages) {
                    try {
                        val appInfo = pkg.applicationInfo ?: continue
                        if (pkg.packageName == packageName) continue

                        val isSystem = (appInfo.flags and
                            android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                        val isUpdatedSystem = (appInfo.flags and
                            android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                        if (isSystem && !isUpdatedSystem) continue

                        val appName = try {
                            pm.getApplicationLabel(appInfo).toString()
                        } catch (_: Exception) { pkg.packageName }

                        val uid = appInfo.uid
                        val pkgName = pkg.packageName

                        // ── Granted sensor permissions ───────────────────────
                        val grantedSensors = mutableListOf<String>()
                        val reqPerms = pkg.requestedPermissions ?: emptyArray()
                        val reqFlags = pkg.requestedPermissionsFlags ?: IntArray(0)
                        for (i in reqPerms.indices) {
                            val perm = reqPerms[i]
                            if (perm !in sensorPermissions) continue
                            val isGranted = i < reqFlags.size &&
                                (reqFlags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                            if (isGranted) grantedSensors.add(perm)
                        }

                        // ── checkOpNoThrow: is the op currently allowed? ──────
                        // MODE_ALLOWED = 0 → op is granted and not blocked
                        // Combined with foreground state → active detection
                        val camOp = aom.checkOpNoThrow(
                            AppOpsManager.OPSTR_CAMERA, uid, pkgName)
                        val micOp = aom.checkOpNoThrow(
                            AppOpsManager.OPSTR_RECORD_AUDIO, uid, pkgName)
                        val locOp = aom.checkOpNoThrow(
                            AppOpsManager.OPSTR_FINE_LOCATION, uid, pkgName)

                        val camAllowed = camOp == AppOpsManager.MODE_ALLOWED
                        val micAllowed = micOp == AppOpsManager.MODE_ALLOWED
                        val locAllowed = locOp == AppOpsManager.MODE_ALLOWED

                        val isInFgNow    = foregroundNow.contains(pkgName)
                        val isInFgRecent = foregroundRecent.contains(pkgName)

                        // ACTIVE NOW: op allowed AND app is in foreground right now
                        val isCameraActiveNow   = camAllowed && isInFgNow
                        val isMicActiveNow      = micAllowed && isInFgNow
                        val isLocationActiveNow = locAllowed && isInFgNow

                        // RECENT: op allowed AND app was in foreground last 60s
                        val isCameraRecent      = camAllowed && isInFgRecent
                        val isMicRecent         = micAllowed && isInFgRecent
                        val isLocationRecent    = locAllowed && isInFgRecent

                        val bgTimeMs  = usageMap[pkgName] ?: 0L
                        val bgTimeHrs = bgTimeMs / 3600000.0

                        if (isCameraActiveNow || isMicActiveNow) {
                            Log.d(TAG, "🔴 ACTIVE: $pkgName cam=$isCameraActiveNow mic=$isMicActiveNow")
                        }

                        list.add(hashMapOf(
                            "packageName"           to pkgName,
                            "appName"               to appName,
                            "grantedSensors"        to grantedSensors,
                            "isCurrentlyRunning"    to (isCameraActiveNow || isMicActiveNow || isLocationActiveNow),
                            "backgroundTimeHrs"     to bgTimeHrs,
                            "isSystemApp"           to isSystem,
                            "isCameraActiveNow"     to isCameraActiveNow,
                            "isMicActiveNow"        to isMicActiveNow,
                            "isLocationActiveNow"   to isLocationActiveNow,
                            "isCameraRecent"        to isCameraRecent,
                            "isMicRecent"           to isMicRecent,
                            "isLocationRecent"      to isLocationRecent,
                        ))
                    } catch (e: Exception) {
                        Log.w(TAG, "Skip ${pkg.packageName}: ${e.message}")
                    }
                }

                Log.d(TAG, "getUserAppsUsingSensors: returning ${list.size} apps")
                runOnUiThread { result.success(list) }

            } catch (e: Exception) {
                Log.e(TAG, "getUserAppsUsingSensors ERROR", e)
                runOnUiThread { result.error("APP_SCAN_FAILED", e.message, null) }
            }
        }.start()
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CHECK SENSOR IN USE  (no system permission required)
    //
    //  Detects whether camera / microphone is in use RIGHT NOW using
    //  three independent signals that work without @hide APIs:
    //
    //  Signal 1 — /proc/asound/*/*/status  (mic)
    //    The ALSA subsystem writes "RUNNING" to this file when any app
    //    has an open audio capture stream. Readable by all apps.
    //
    //  Signal 2 — SensorPrivacyManager (Android 12+)
    //    Public API that tells you if camera/mic toggle is on/off.
    //    If the toggle is ON (privacy enabled) → no app can use it.
    //    If it's OFF → hardware is accessible.
    //
    //  Signal 3 — Try to open Camera2 / AudioRecord yourself
    //    If opening fails with "camera in use" or "recorder in use"
    //    → another app has it open right now.
    //
    //  Returns: Map with isMicInUse, isCameraInUse, suspectApps[]
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleCheckSensorInUse(result: MethodChannel.Result) {
        Thread {
            val isMicInUse    = checkMicInUse()
            val isCameraInUse = checkCameraInUse()

            Log.d(TAG, "SensorInUse: mic=$isMicInUse camera=$isCameraInUse")

            // If a sensor IS in use, find which apps have that permission granted
            // These are the "suspect" apps — one of them is the user
            val suspectApps = mutableListOf<Map<String, Any>>()

            if (isMicInUse || isCameraInUse) {
                try {
                    val pm = packageManager
                    val flags = PackageManager.GET_PERMISSIONS
                    val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
                    } else {
                        @Suppress("DEPRECATION")
                        pm.getInstalledPackages(flags)
                    }

                    for (pkg in packages) {
                        try {
                            if (pkg.packageName == packageName) continue
                            val appInfo = pkg.applicationInfo ?: continue
                            val isSystem = (appInfo.flags and
                                android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                            val isUpdatedSystem = (appInfo.flags and
                                android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                            if (isSystem && !isUpdatedSystem) continue

                            // Skip Google infrastructure even if updated
                            val gInfra = listOf(
                                "com.google.android.gms",
                                "com.google.android.gsf",
                                "com.google.android.webview",
                                "com.google.android.permissioncontroller",
                                "com.google.android.ext.services",
                                "com.android.vending",
                            )
                            if (gInfra.any { pkg.packageName == it || pkg.packageName.startsWith("$it.") }) continue

                            val reqPerms = pkg.requestedPermissions ?: emptyArray()
                            val reqFlags = pkg.requestedPermissionsFlags ?: IntArray(0)

                            var hasCameraGranted = false
                            var hasMicGranted    = false

                            for (i in reqPerms.indices) {
                                val granted = i < reqFlags.size &&
                                    (reqFlags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                                if (!granted) continue
                                when (reqPerms[i]) {
                                    "android.permission.CAMERA"       -> hasCameraGranted = true
                                    "android.permission.RECORD_AUDIO" -> hasMicGranted    = true
                                }
                            }

                            val isSuspect = (isCameraInUse && hasCameraGranted) ||
                                            (isMicInUse    && hasMicGranted)
                            if (!isSuspect) continue

                            val appName = try {
                                pm.getApplicationLabel(appInfo).toString()
                            } catch (_: Exception) { pkg.packageName }

                            // Also check foreground via UsageEvents (best effort)
                            val isLikelyActive = isInForegroundRecently(pkg.packageName, 30_000L)

                            suspectApps.add(hashMapOf(
                                "packageName"    to pkg.packageName,
                                "appName"        to appName,
                                "hasCameraGrant" to hasCameraGranted,
                                "hasMicGrant"    to hasMicGranted,
                                "isLikelyActive" to isLikelyActive,
                            ))
                        } catch (_: Exception) {}
                    }

                    // Sort: likely-active apps first
                    suspectApps.sortByDescending {
                        if ((it["isLikelyActive"] as? Boolean) == true) 1 else 0
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "suspectApps scan failed: ${e.message}")
                }
            }

            runOnUiThread {
                result.success(hashMapOf(
                    "isMicInUse"    to isMicInUse,
                    "isCameraInUse" to isCameraInUse,
                    "suspectApps"   to suspectApps,
                    "timestamp"     to System.currentTimeMillis(),
                ))
            }
        }.start()
    }

    // ── Mic detection ─────────────────────────────────────────────────────
    //
    //  API 28+: AudioManager.isMicrophoneMuted() is NOT what we want.
    //  API 28+: AudioManager.getActiveRecordingConfigurations() — THIS IS IT.
    //    Returns a list of all active AudioRecord sessions across ALL apps.
    //    If the list is non-empty → some app has the mic open right now.
    //    This is 100% public API, works for background apps too.
    //
    //  API < 28 fallback: /proc/asound status files.
    private fun checkMicInUse(): Boolean {

        // ── Primary: AudioManager.getActiveRecordingConfigurations() ─────
        // Available API 24+. Returns ALL active recording sessions system-wide.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                val am = getSystemService(Context.AUDIO_SERVICE) as android.media.AudioManager
                val configs = am.activeRecordingConfigurations
                Log.d(TAG, "MIC_PROBE: activeRecordingConfigurations = ${configs.size} session(s)")

                // clientUid only available API 28+. Use reflection to avoid
                // compile-time resolution error on lower API targets.
                val myUid = android.os.Process.myUid()
                val othersRecording = if (Build.VERSION.SDK_INT >= 28) {
                    configs.any { cfg ->
                        try {
                            val uid = cfg.javaClass.getMethod("getClientUid").invoke(cfg) as? Int
                            Log.d(TAG, "MIC_PROBE: session uid=$uid source=${cfg.clientAudioSource}")
                            uid != null && uid != myUid
                        } catch (_: Exception) { true }
                    }
                } else {
                    configs.isNotEmpty()
                }

                if (othersRecording) {
                    Log.d(TAG, "MIC_PROBE: ✅ ANOTHER APP is recording audio right now")
                    return true
                }
                if (configs.isNotEmpty()) {
                    Log.d(TAG, "MIC_PROBE: only our own app is recording (${configs.size} session)")
                }
                Log.d(TAG, "MIC_PROBE: no other app recording")
                return false
            } catch (e: Exception) {
                Log.w(TAG, "MIC_PROBE: getActiveRecordingConfigurations failed: ${e.message}")
                // Fall through to /proc fallback
            }
        }

        // ── Fallback: /proc/asound (API < 24) ────────────────────────────
        var running = false
        try {
            val asoundDir = File("/proc/asound")
            if (!asoundDir.exists()) return false
            outer@ for (cardDir in asoundDir.listFiles() ?: emptyArray()) {
                if (!cardDir.isDirectory || !cardDir.name.startsWith("card")) continue
                for (pcmDir in cardDir.listFiles() ?: emptyArray()) {
                    if (!pcmDir.isDirectory || !pcmDir.name.endsWith("c")) continue
                    for (subDir in pcmDir.listFiles() ?: emptyArray()) {
                        if (!subDir.isDirectory || !subDir.name.startsWith("sub")) continue
                        val statusFile = File(subDir, "status")
                        if (!statusFile.exists()) continue
                        val text = try { statusFile.readText() } catch (_: Exception) { continue }
                        if (text.contains("RUNNING", ignoreCase = true)) {
                            Log.d(TAG, "MIC_PROBE: /proc RUNNING at ${statusFile.path}")
                            running = true
                            break@outer
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "MIC_PROBE: /proc scan failed: ${e.message}")
        }
        return running
    }

    // ── Camera detection ──────────────────────────────────────────────────
    //
    //  Method A: CameraManager.AvailabilityCallback
    //    Register a callback → onCameraUnavailable fires immediately for any
    //    camera currently held by another app. Much more reliable than trying
    //    to open it (which requires us to also hold the camera permission and
    //    can interfere with the other app).
    //
    //  Method B: Camera2 open attempt (fallback).
    private fun checkCameraInUse(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) return false
        try {
            val cm = getSystemService(Context.CAMERA_SERVICE)
                as? android.hardware.camera2.CameraManager ?: return false

            val ids = cm.cameraIdList
            if (ids.isEmpty()) return false

            // ── Method A: AvailabilityCallback ───────────────────────────
            // onCameraUnavailable(id) fires synchronously for cameras that
            // are currently held. We collect them over 300ms.
            val unavailableIds = mutableSetOf<String>()
            val latch = java.util.concurrent.CountDownLatch(1)

            val cb = object : android.hardware.camera2.CameraManager.AvailabilityCallback() {
                override fun onCameraAvailable(cameraId: String) {
                    // Available = not in use, nothing to do
                }
                override fun onCameraUnavailable(cameraId: String) {
                    Log.d(TAG, "Camera UNAVAILABLE (in use): $cameraId")
                    unavailableIds.add(cameraId)
                }
            }

            val handlerThread = android.os.HandlerThread("CamAvailCheck")
            handlerThread.start()
            val handler = android.os.Handler(handlerThread.looper)

            cm.registerAvailabilityCallback(cb, handler)
            // Wait 400ms — callbacks fire synchronously on registration
            // for any camera that is currently unavailable
            Thread.sleep(400)
            cm.unregisterAvailabilityCallback(cb)
            handlerThread.quitSafely()

            if (unavailableIds.isNotEmpty()) {
                Log.d(TAG, "Camera(s) in use: $unavailableIds")
                return true
            }

            Log.d(TAG, "All cameras available (not in use)")
            return false

        } catch (e: Exception) {
            Log.w(TAG, "checkCameraInUse: ${e.message}")
            return false
        }
    }

    // ── Foreground check via UsageEvents ─────────────────────────────────
    private fun isInForegroundRecently(pkgName: String, windowMs: Long): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return false
        return try {
            val usm = getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
                ?: return false
            val now    = System.currentTimeMillis()
            val events = usm.queryEvents(now - windowMs, now) ?: return false
            val event  = android.app.usage.UsageEvents.Event()
            var lastType = -1
            while (events.hasNextEvent()) {
                events.getNextEvent(event)
                if (event.packageName == pkgName) lastType = event.eventType
            }
            lastType == android.app.usage.UsageEvents.Event.MOVE_TO_FOREGROUND
        } catch (_: Exception) { false }
    }

    private fun handleGetActiveSensors(result: MethodChannel.Result) {
        try {
            val sm = getSystemService(SENSOR_SERVICE) as SensorManager
            val sensors = sm.getSensorList(Sensor.TYPE_ALL)

            val sensorList = sensors.map { sensor ->
                mapOf(
                    "name"     to sensor.name,
                    "vendor"   to sensor.vendor,
                    "type"     to sensor.type,
                    "typeName" to sensorTypeName(sensor.type),
                    "power"    to sensor.power,   // mA drain
                    "maxRange" to sensor.maximumRange,
                )
            }
            result.success(sensorList)
        } catch (e: Exception) {
            Log.e(TAG, "getActiveSensors failed", e)
            result.error("SENSOR_ERROR", e.message, null)
        }
    }

    private fun sensorTypeName(type: Int): String = when (type) {
        Sensor.TYPE_ACCELEROMETER        -> "Accelerometer"
        Sensor.TYPE_GYROSCOPE            -> "Gyroscope"
        Sensor.TYPE_MAGNETIC_FIELD       -> "Magnetometer"
        Sensor.TYPE_LIGHT                -> "Light"
        Sensor.TYPE_PROXIMITY            -> "Proximity"
        Sensor.TYPE_PRESSURE             -> "Barometer"
        Sensor.TYPE_GRAVITY              -> "Gravity"
        Sensor.TYPE_LINEAR_ACCELERATION  -> "Linear Acceleration"
        Sensor.TYPE_ROTATION_VECTOR      -> "Rotation Vector"
        Sensor.TYPE_AMBIENT_TEMPERATURE  -> "Temperature"
        Sensor.TYPE_HEART_RATE           -> "Heart Rate"
        Sensor.TYPE_STEP_COUNTER         -> "Step Counter"
        Sensor.TYPE_STEP_DETECTOR        -> "Step Detector"
        else                             -> "Sensor($type)"
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  APP PERMISSIONS (for a specific package)
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleGetAppPermissions(call: io.flutter.plugin.common.MethodCall, result: MethodChannel.Result) {
        try {
            val pkgName = call.argument<String>("packageName")
                ?: return result.error("MISSING_ARG", "packageName required", null)

            val pkg = packageManager.getPackageInfo(pkgName, PackageManager.GET_PERMISSIONS)
            val perms  = pkg.requestedPermissions ?: emptyArray()
            val flags  = pkg.requestedPermissionsFlags ?: IntArray(0)

            val permList = perms.mapIndexed { i, perm ->
                val isGranted = i < flags.size && (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                mapOf(
                    "permission" to perm,
                    "isGranted"  to isGranted,
                    "shortName"  to perm.substringAfterLast("."),
                )
            }
            result.success(permList)
        } catch (e: Exception) {
            Log.e(TAG, "getAppPermissions failed", e)
            result.error("PERM_ERROR", e.message, null)
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  APP NETWORK USAGE (per-app TX/RX via TrafficStats UID)
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleGetAppNetworkUsage(result: MethodChannel.Result) {
        try {
            val pm = packageManager
            val packages = pm.getInstalledPackages(0)
            val usageList = mutableListOf<Map<String, Any>>()

            for (pkg in packages) {
                try {
                    // Never report on our own app
                    if (pkg.packageName == packageName) continue

                    val appInfo = pkg.applicationInfo ?: continue

                    // Skip system apps
                    val isSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    val isUpdatedSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    if (isSystem && !isUpdatedSystem) continue

                    val uid = appInfo.uid
                    val tx  = TrafficStats.getUidTxBytes(uid)
                    val rx  = TrafficStats.getUidRxBytes(uid)

                    if (tx <= 0 && rx <= 0) continue

                    val appName = try {
                        pm.getApplicationLabel(appInfo).toString()
                    } catch (_: Exception) { pkg.packageName }

                    usageList.add(mapOf(
                        "packageName" to pkg.packageName,
                        "appName"     to appName,
                        "uid"         to uid,
                        "txBytes"     to tx,
                        "rxBytes"     to rx,
                        "totalBytes"  to (tx + rx),
                    ))
                } catch (_: Exception) {}
            }

            usageList.sortByDescending { (it["totalBytes"] as? Long) ?: 0L }
            result.success(usageList)
        } catch (e: Exception) {
            Log.e(TAG, "getAppNetworkUsage failed", e)
            result.error("NET_USAGE_ERROR", e.message, null)
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  EXISTING HANDLERS (unchanged from previous version)
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleGetCpuUsage(result: MethodChannel.Result) {
        try { result.success(readCpuUsage()) }
        catch (e: Exception) { result.error("CPU_ERROR", e.message, null) }
    }

    private fun readCpuUsage(): Double {
        return try {
            val s1 = parseProcStat(); Thread.sleep(250); val s2 = parseProcStat()
            if (s1.isEmpty() || s2.isEmpty()) return -1.0
            val dTotal = (s2.sum() - s1.sum()).toDouble()
            val dIdle  = (s2.getOrElse(3){0L} - s1.getOrElse(3){0L}).toDouble()
            if (dTotal <= 0) 0.0 else ((dTotal - dIdle) / dTotal * 100.0).coerceIn(0.0, 100.0)
        } catch (_: Exception) { -1.0 }
    }

    private fun parseProcStat(): List<Long> = try {
        RandomAccessFile("/proc/stat", "r").use { it.readLine() }
            ?.trim()?.split("\\s+".toRegex())?.drop(1)?.mapNotNull { it.toLongOrNull() } ?: emptyList<Long>()
    } catch (_: Exception) { emptyList<Long>() }

    private fun handleGetMemoryInfo(result: MethodChannel.Result) {
        try {
            val am = getSystemService(ACTIVITY_SERVICE) as ActivityManager
            val mi = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
            result.success(mapOf("totalRam" to mi.totalMem, "availableRam" to mi.availMem,
                "lowMemory" to mi.lowMemory, "threshold" to mi.threshold))
        } catch (e: Exception) { result.error("MEM_ERROR", e.message, null) }
    }

    private fun handleGetNetworkConnections(result: MethodChannel.Result) {
        try {
            val conns = mutableListOf<Map<String, String>>()
            conns += parseProcNetTcp("/proc/net/tcp")
            conns += parseProcNetTcp("/proc/net/tcp6")
            result.success(conns)
        } catch (e: Exception) { result.error("NET_ERROR", e.message, null) }
    }

    private fun parseProcNetTcp(path: String): List<Map<String, String>> {
        val results = mutableListOf<Map<String, String>>()
        val file = File(path)
        if (!file.exists() || !file.canRead()) return results
        try {
            file.bufferedReader().useLines { lines ->
                lines.drop(1).forEach { line ->
                    val parts = line.trim().split("\\s+".toRegex())
                    if (parts.size >= 8 && parts[3] == "01") {
                        results.add(mapOf("localAddress" to decodeHexAddress(parts[1]),
                            "remoteAddress" to decodeHexAddress(parts[2]),
                            "state" to parts[3], "uid" to parts[7],
                            "source" to path.substringAfterLast("/")))
                    }
                }
            }
        } catch (_: Exception) {}
        return results
    }

    private fun decodeHexAddress(hexAddrPort: String): String {
        return try {
            val colon   = hexAddrPort.indexOf(':')
            if (colon < 0) return hexAddrPort
            val addrHex = hexAddrPort.substring(0, colon)
            val port    = hexAddrPort.substring(colon + 1).toInt(16)
            val addr = when (addrHex.length) {
                8  -> (0 until 4).joinToString(".") { i -> addrHex.substring(i*2, i*2+2).toInt(16).toString() }
                32 -> (0 until 4).joinToString(":") { g ->
                    val off = g*8; val seg = addrHex.substring(off, off+8)
                    (3 downTo 0).joinToString("") { b -> seg.substring(b*2, b*2+2) }
                }
                else -> addrHex
            }
            "$addr:$port"
        } catch (_: Exception) { hexAddrPort }
    }

    private fun handleGetNetworkDataUsage(result: MethodChannel.Result) {
        try {
            val u = TrafficStats.UNSUPPORTED.toLong()
            fun safe(v: Long) = if (v == u) -1L else v
            result.success(mapOf("totalTxBytes" to safe(TrafficStats.getTotalTxBytes()),
                "totalRxBytes" to safe(TrafficStats.getTotalRxBytes()),
                "mobileTxBytes" to safe(TrafficStats.getMobileTxBytes()),
                "mobileRxBytes" to safe(TrafficStats.getMobileRxBytes())))
        } catch (e: Exception) { result.error("TRAFFIC_ERROR", e.message, null) }
    }

    private fun handleGetInstalledApps(result: MethodChannel.Result) {
        try {
            val pm = packageManager
            result.success(pm.getInstalledPackages(PackageManager.GET_META_DATA).mapNotNull { pkg ->
                try {
                    val ai = pkg.applicationInfo ?: return@mapNotNull null
                    val isSystem = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    mapOf("packageName" to pkg.packageName, "appName" to pm.getApplicationLabel(ai).toString(),
                        "isSystemApp" to isSystem, "firstInstallTime" to pkg.firstInstallTime,
                        "lastUpdateTime" to pkg.lastUpdateTime, "versionName" to (pkg.versionName ?: "unknown"),
                        "targetSdkVersion" to ai.targetSdkVersion)
                } catch (_: Exception) { null }
            })
        } catch (e: Exception) { result.error("APPS_ERROR", e.message, null) }
    }

    private fun handleGetRunningProcesses(result: MethodChannel.Result) {
        try {
            val am = getSystemService(ACTIVITY_SERVICE) as ActivityManager
            result.success((am.runningAppProcesses ?: emptyList<android.app.ActivityManager.RunningAppProcessInfo>()).map { proc ->
                mapOf("pid" to proc.pid, "processName" to proc.processName,
                    "importance" to proc.importance, "importanceReasonCode" to proc.importanceReasonCode,
                    "pkgList" to (proc.pkgList?.toList() ?: emptyList<String>()))
            })
        } catch (e: Exception) { result.error("PROC_ERROR", e.message, null) }
    }

    private fun handleGetUsageStats(result: MethodChannel.Result) {
        try {
            if (!hasUsageStatsPermission()) {
                result.error("USAGE_STATS_PERMISSION", "Permission not granted", null); return
            }
            val usm = getSystemService(USAGE_STATS_SERVICE) as UsageStatsManager
            val now = System.currentTimeMillis()
            val stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY,
                now - 24*60*60*1000L, now)
                ?.filter { it.totalTimeInForeground > 0 }
                ?.map { s -> mapOf(
                    "packageName"           to s.packageName,
                    "totalTimeInForeground" to s.totalTimeInForeground,
                    "lastTimeUsed"          to s.lastTimeUsed,
                )}
                ?: emptyList<Map<String, Any>>()
            result.success(stats)
        } catch (e: Exception) { result.error("USAGE_ERROR", e.message, null) }
    }

    private fun hasUsageStatsPermission(): Boolean {
        val aom = getSystemService(APP_OPS_SERVICE) as AppOpsManager
        return aom.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS,
            android.os.Process.myUid(), packageName) == AppOpsManager.MODE_ALLOWED
    }

    private fun handleGetGrantedPermissions(result: MethodChannel.Result) {
        try {
            val pkg = packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            result.success(pkg.requestedPermissions?.filterIndexed { i, _ ->
                (pkg.requestedPermissionsFlags?.getOrNull(i) ?: 0) and
                PackageManager.GET_PERMISSIONS != 0 } ?: emptyList<String>())
        } catch (e: Exception) { result.error("PERM_ERROR", e.message, null) }
    }

    private fun handleGetBatteryInfo(result: MethodChannel.Result) {
        try {
            val bs = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            val level = bs?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
            val scale = bs?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
            result.success(mapOf("level" to level, "scale" to scale,
                "percentage" to if (level >= 0 && scale > 0) level * 100.0 / scale else -1.0,
                "status"  to (bs?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1),
                "plugged" to (bs?.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) ?: -1),
                "temperatureTenths" to (bs?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1) ?: -1),
                "voltage" to (bs?.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1) ?: -1),
                "health"  to (bs?.getIntExtra(BatteryManager.EXTRA_HEALTH, -1) ?: -1)))
        } catch (e: Exception) { result.error("BATTERY_ERROR", e.message, null) }
    }

    private fun handleIsDeviceRooted(result: MethodChannel.Result) {
        try { result.success(checkIsRooted()) }
        catch (e: Exception) { result.success(false) }
    }

    private fun checkIsRooted(): Boolean {
        val suPaths = listOf("/system/bin/su","/system/xbin/su","/sbin/su",
            "/system/app/Superuser.apk","/data/local/su","/data/local/bin/su",
            "/system/sd/xbin/su","/system/bin/.ext/.su")
        if (suPaths.any { File(it).exists() }) return true
        if (Build.TAGS?.contains("test-keys") == true) return true
        try {
            val out = Runtime.getRuntime().exec("mount").inputStream.bufferedReader().readText()
            if (out.contains("/system") && out.contains(" rw,")) return true
        } catch (_: Exception) {}
        listOf("com.topjohnwu.magisk","com.noshufou.android.su","eu.chainfire.supersu",
            "com.koushikdutta.superuser").forEach { pkg ->
            try { packageManager.getPackageInfo(pkg, 0); return true }
            catch (_: PackageManager.NameNotFoundException) {}
        }
        return false
    }

    private fun handleIsDeveloperOptionsEnabled(result: MethodChannel.Result) {
        try { result.success(Settings.Global.getInt(contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1)
        } catch (_: Exception) { result.success(false) }
    }

    private fun handleIsUsbDebuggingEnabled(result: MethodChannel.Result) {
        try { result.success(Settings.Global.getInt(contentResolver,
            Settings.Global.ADB_ENABLED, 0) == 1)
        } catch (_: Exception) { result.success(false) }
    }

    private fun handleIsIgnoringBatteryOptimizations(result: MethodChannel.Result) {
        try { result.success((getSystemService(POWER_SERVICE) as PowerManager)
            .isIgnoringBatteryOptimizations(packageName))
        } catch (_: Exception) { result.success(false) }
    }

    private fun handleRequestBatteryExemption(result: MethodChannel.Result) {
        try {
            startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                .apply { data = android.net.Uri.parse("package:$packageName") })
            result.success(true)
        } catch (e: Exception) { result.success(false) }
    }

    private fun handleGetSecurityFlags(result: MethodChannel.Result) {
        try {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            result.success(mapOf(
                "isRooted" to checkIsRooted(),
                "isDeveloperOptionsEnabled" to (Settings.Global.getInt(contentResolver,
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1),
                "isUsbDebuggingEnabled" to (Settings.Global.getInt(contentResolver,
                    Settings.Global.ADB_ENABLED, 0) == 1),
                "isIgnoringBatteryOptimizations" to pm.isIgnoringBatteryOptimizations(packageName),
                "hasUsageStatsPermission" to hasUsageStatsPermission()))
        } catch (e: Exception) { result.error("FLAGS_ERROR", e.message, null) }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  ACTIVE ACCESSIBILITY SERVICES
    //  Uses AccessibilityManager.getEnabledAccessibilityServiceList()
    //  This is the REAL check — not just declared in manifest, but actually
    //  enabled by the user in Settings → Accessibility.
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleGetActiveAccessibilityServices(result: MethodChannel.Result) {
        try {
            val am = getSystemService(ACCESSIBILITY_SERVICE)
                as android.view.accessibility.AccessibilityManager
            val services = am.getEnabledAccessibilityServiceList(
                android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            )
            val pm = packageManager
            val list = services.mapNotNull { svc ->
                try {
                    val ci = svc.resolveInfo?.serviceInfo ?: return@mapNotNull null
                    val appInfo = pm.getApplicationInfo(ci.packageName, 0)
                    val isSystem = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    val appName = try { pm.getApplicationLabel(appInfo).toString() }
                                  catch (_: Exception) { ci.packageName }
                    mapOf(
                        "packageName"  to ci.packageName,
                        "serviceName"  to ci.name,
                        "appName"      to appName,
                        "isSystemApp"  to isSystem,
                        "capabilities" to svc.capabilities,
                        "description"  to (svc.loadDescription(pm)?.toString() ?: ""),
                    )
                } catch (_: Exception) { null }
            }
            result.success(list)
        } catch (e: Exception) {
            result.error("ACCESSIBILITY_ERROR", e.message, null)
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SCREEN RECORDING DETECTION
    //  MediaProjectionManager on Android 5+.
    //  On Android 14+ uses MediaProjectionManager.isMediaProjectionActive().
    //  On earlier versions: detect via VirtualDisplay or MediaRecorder state.
    //  Also checks for known screen recorder packages.
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleIsScreenRecordingActive(result: MethodChannel.Result) {
        try {
            var isRecording = false
            val suspectApps = mutableListOf<String>()

            // Method 1: Android 14+ direct API
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) { // API 34
                try {
                    val mpm = getSystemService(Context.MEDIA_PROJECTION_SERVICE)
                        as android.media.projection.MediaProjectionManager
                    // getActiveProjectionInfo() is API 34+
                    val info = mpm.javaClass.getMethod("getActiveProjectionInfo")
                        .invoke(mpm)
                    if (info != null) {
                        isRecording = true
                        Log.d(TAG, "Screen recording detected via MediaProjection API")
                    }
                } catch (_: Exception) {}
            }

            // Method 2: Check known screen recorder apps that are currently running
            val knownRecorders = listOf(
                "com.android.screenrecord",
                "com.google.android.screenrecorder",
                "com.miui.screenrecorder",
                "com.samsung.android.app.screenrecorder",
                "com.oneplus.screenrecorder",
                "com.huawei.screenrecorder",
                "net.biscuitlabs.screenrecorder",
                "com.ilos.recorder",
                "com.hecorat.screenrecorder",
                "com.lollipop.screenrecorder",
                "com.mobizen.mirroring",
                "com.apowersoft.android.record",
            )
            val am = getSystemService(ACTIVITY_SERVICE) as android.app.ActivityManager
            val running = am.runningAppProcesses?.flatMap {
                it.pkgList?.toList() ?: emptyList()
            }?.toSet() ?: emptySet()

            for (pkg in knownRecorders) {
                if (running.contains(pkg)) {
                    isRecording = true
                    try {
                        val ai = packageManager.getApplicationInfo(pkg, 0)
                        suspectApps.add(pm_label(ai))
                    } catch (_: Exception) { suspectApps.add(pkg) }
                }
            }

            // Method 3: Check for CAPTURE_VIDEO_OUTPUT or CAPTURE_SECURE_VIDEO_OUTPUT
            // processes — these are used by screen capture tools
            try {
                val flags = PackageManager.GET_PERMISSIONS
                val pkgs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                    packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
                else @Suppress("DEPRECATION") packageManager.getInstalledPackages(flags)

                for (pkg in pkgs) {
                    val perms = pkg.requestedPermissions ?: continue
                    val ai = pkg.applicationInfo ?: continue
                    if (pkg.packageName == packageName) continue
                    val isSystem = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    val isUpdated = (ai.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    if (isSystem && !isUpdated) continue
                    if ("android.permission.CAPTURE_VIDEO_OUTPUT" in perms ||
                        "android.permission.CAPTURE_AUDIO_OUTPUT" in perms) {
                        val name = pm_label(ai)
                        if (!suspectApps.contains(name)) suspectApps.add(name)
                    }
                }
            } catch (_: Exception) {}

            result.success(mapOf(
                "isRecording"  to isRecording,
                "suspectApps"  to suspectApps,
                "method"       to if (isRecording) "detected" else "not_detected",
            ))
        } catch (e: Exception) {
            result.success(mapOf("isRecording" to false, "suspectApps" to emptyList<String>()))
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  CLIPBOARD MONITORING DETECTION
    //  ClipboardManager.OnPrimaryClipChangedListener can be registered by
    //  ANY app without a permission — a classic credential theft vector.
    //  We detect: apps with clipboard access + running in background.
    //  Android 10+ restricts clipboard reads, but listener registration is free.
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleGetClipboardInfo(result: MethodChannel.Result) {
        try {
            val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
            val hasClip = cm.hasPrimaryClip()
            val clipType = cm.primaryClipDescription?.getMimeType(0) ?: "none"

            // Check for apps running in background that also have
            // READ_CLIPBOARD or are known clipboard sniffers
            val am = getSystemService(ACTIVITY_SERVICE) as android.app.ActivityManager
            val bgProcs = am.runningAppProcesses?.filter { p ->
                p.importance >= android.app.ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE &&
                p.importance < android.app.ActivityManager.RunningAppProcessInfo.IMPORTANCE_GONE
            }?.flatMap { it.pkgList?.toList() ?: emptyList() }?.toSet() ?: emptySet()

            // Packages in background that also target Clipboard access patterns
            val suspectClipApps = mutableListOf<Map<String, Any>>()
            val pm = packageManager
            val flags = PackageManager.GET_PERMISSIONS
            val pkgs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
            else @Suppress("DEPRECATION") pm.getInstalledPackages(flags)

            for (pkg in pkgs) {
                try {
                    val ai = pkg.applicationInfo ?: continue
                    if (pkg.packageName == packageName) continue
                    val isSystem = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    val isUpdated = (ai.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    if (isSystem && !isUpdated) continue
                    if (!bgProcs.contains(pkg.packageName)) continue

                    // Clipboard sniffers typically also have READ_CONTACTS or INTERNET
                    val perms = pkg.requestedPermissions?.toSet() ?: continue
                    val hasInputMethod = perms.contains("android.permission.BIND_INPUT_METHOD")
                    val hasAccessibility = perms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
                    // A background app with input method OR accessibility CAN read clipboard
                    if (hasInputMethod || hasAccessibility) {
                        val name = try { pm.getApplicationLabel(ai).toString() }
                                   catch (_: Exception) { pkg.packageName }
                        suspectClipApps.add(mapOf(
                            "packageName"    to pkg.packageName,
                            "appName"        to name,
                            "hasInputMethod" to hasInputMethod,
                            "hasAccessibility" to hasAccessibility,
                        ))
                    }
                } catch (_: Exception) {}
            }

            result.success(mapOf(
                "hasClipboardContent" to hasClip,
                "clipType"            to clipType,
                "suspectApps"         to suspectClipApps,
                "suspectCount"        to suspectClipApps.size,
            ))
        } catch (e: Exception) {
            result.error("CLIPBOARD_ERROR", e.message, null)
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  DETAILED SECURITY FLAGS
    //  Extends getSecurityFlags() with:
    //    • Exact active accessibility service count and names
    //    • Active device admin count and packages
    //    • Unknown sources per-app (Android 8+) OR global (Android 7-)
    //    • Battery optimization disabled count
    //    • Mock location enabled
    //    • Verify apps disabled (disables Play Protect scanning)
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleGetDetailedSecurityFlags(result: MethodChannel.Result) {
        try {
            val pm = packageManager
            val cr = contentResolver

            // ── Accessibility services (real enabled count) ───────────────
            val accMgr = getSystemService(ACCESSIBILITY_SERVICE)
                as android.view.accessibility.AccessibilityManager
            val activeAccServices = accMgr.getEnabledAccessibilityServiceList(
                android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            )
            val userAccServices = activeAccServices.filter { svc ->
                try {
                    val ai = pm.getApplicationInfo(svc.resolveInfo?.serviceInfo?.packageName ?: "", 0)
                    (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0
                } catch (_: Exception) { false }
            }

            // ── Device admin (real active list) ──────────────────────────
            val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE)
                as android.app.admin.DevicePolicyManager
            val adminList = dpm.activeAdmins ?: emptyList()
            val userAdmins = adminList.filter { cn ->
                try {
                    val ai = pm.getApplicationInfo(cn.packageName, 0)
                    (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0
                } catch (_: Exception) { false }
            }

            // ── Unknown sources ───────────────────────────────────────────
            val unknownSources = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                // Android 7 and below: global setting
                Settings.Global.getInt(cr, Settings.Global.INSTALL_NON_MARKET_APPS, 0) == 1
            } else {
                // Android 8+: check if any non-system app has INSTALL_PACKAGES granted
                var anyGranted = false
                try {
                    val flags = PackageManager.GET_PERMISSIONS
                    val pkgs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                        pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
                    else @Suppress("DEPRECATION") pm.getInstalledPackages(flags)
                    for (pkg in pkgs) {
                        val ai = pkg.applicationInfo ?: continue
                        val isSystem = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                        if (isSystem) continue
                        val perms  = pkg.requestedPermissions ?: continue
                        val pFlags = pkg.requestedPermissionsFlags ?: continue
                        val idx    = perms.indexOf("android.permission.REQUEST_INSTALL_PACKAGES")
                        if (idx >= 0 && idx < pFlags.size &&
                            (pFlags[idx] and android.content.pm.PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
                            anyGranted = true; break
                        }
                    }
                } catch (_: Exception) {}
                anyGranted
            }

            // ── Battery optimization disabled count ───────────────────────
            val pwm = getSystemService(POWER_SERVICE) as android.os.PowerManager
            var battOptDisabledCount = 0
            try {
                val flags = 0
                val pkgs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                    pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
                else @Suppress("DEPRECATION") pm.getInstalledPackages(flags)
                for (pkg in pkgs) {
                    val ai = pkg.applicationInfo ?: continue
                    val isSystem = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    if (isSystem) continue
                    if (!pwm.isIgnoringBatteryOptimizations(pkg.packageName)) continue
                    battOptDisabledCount++
                }
            } catch (_: Exception) {}

            // ── Mock location ─────────────────────────────────────────────
            val mockLocation = Settings.Secure.getInt(cr,
                Settings.Secure.ALLOW_MOCK_LOCATION, 0) == 1

            // ── Verify apps (Play Protect) ────────────────────────────────
            val verifyApps = Settings.Global.getInt(cr,
                "package_verifier_enable", 1) == 1

            result.success(mapOf(
                "isRooted"                    to checkIsRooted(),
                "isUsbDebuggingEnabled"       to (Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1),
                "isDeveloperOptionsEnabled"   to (Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1),
                "isUnknownSourcesEnabled"     to unknownSources,
                "isMockLocationEnabled"       to mockLocation,
                "isVerifyAppsEnabled"         to verifyApps,
                "hasUsageStatsPermission"     to hasUsageStatsPermission(),
                "isIgnoringBatteryOptimizations" to pwm.isIgnoringBatteryOptimizations(packageName),
                "batteryOptDisabledCount"     to battOptDisabledCount,
                "activeAccessibilityServiceCount" to userAccServices.size,
                "activeAccessibilityServices" to userAccServices.map { svc ->
                    svc.resolveInfo?.serviceInfo?.packageName ?: ""
                }.filter { it.isNotEmpty() },
                "isAccessibilityServiceActive" to userAccServices.isNotEmpty(),
                "activeDeviceAdminCount"      to userAdmins.size,
                "isDeviceAdminActive"         to userAdmins.isNotEmpty(),
                "activeDeviceAdmins"          to userAdmins.map { it.packageName },
            ))
        } catch (e: Exception) {
            result.error("DETAILED_FLAGS_ERROR", e.message, null)
        }
    }

    // ── private helper ─────────────────────────────────────────────────────
    private fun pm_label(ai: android.content.pm.ApplicationInfo): String {
        return try { packageManager.getApplicationLabel(ai).toString() }
               catch (_: Exception) { ai.packageName }
    }



    // ═══════════════════════════════════════════════════════════════════════
    //  VPN DETECTION
    //  Detects active VPN connections — used by RATs to tunnel exfiltrated
    //  data through encrypted channels that bypass network monitors.
    //  Detection methods:
    //    1. ConnectivityManager.getActiveNetwork() + NetworkCapabilities
    //       (NET_CAPABILITY_NOT_VPN = false means VPN is active)
    //    2. NetworkInterface scan for tun0 / ppp0 / wg0 interfaces
    //    3. Scan installed apps for VPN service declarations
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleGetVpnStatus(result: MethodChannel.Result) {
        try {
            var vpnActive   = false
            var vpnPackage  = ""
            var vpnAppName  = ""
            val vpnApps     = mutableListOf<Map<String, Any>>()
            val vpnIfaces   = mutableListOf<String>()

            // Method 1: ConnectivityManager — most reliable on Android 6+
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    val cm = getSystemService(CONNECTIVITY_SERVICE)
                        as android.net.ConnectivityManager
                    val network = cm.activeNetwork
                    val caps    = network?.let { cm.getNetworkCapabilities(it) }
                    if (caps != null &&
                        !caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                        vpnActive = true
                        Log.d(TAG, "VPN detected via ConnectivityManager")
                    }
                } catch (_: Exception) {}
            }

            // Method 2: NetworkInterface scan for VPN tunnel interfaces
            try {
                val ifaces = java.net.NetworkInterface.getNetworkInterfaces()
                ifaces?.let { e ->
                    while (e.hasMoreElements()) {
                        val iface = e.nextElement()
                        val name = iface.name.lowercase()
                        // tun0 = OpenVPN, ppp0 = PPTP, wg0 = WireGuard,
                        // tun1 = common VPN, ipsec = IPSec VPN
                        if (name.startsWith("tun") || name.startsWith("ppp") ||
                            name.startsWith("wg")  || name.startsWith("ipsec") ||
                            name.startsWith("vpn")) {
                            if (iface.isUp) {
                                vpnActive = true
                                vpnIfaces.add(iface.name)
                                Log.d(TAG, "VPN interface detected: ${iface.name}")
                            }
                        }
                    }
                }
            } catch (_: Exception) {}

            // Method 3: Find installed apps that have BIND_VPN_SERVICE
            try {
                val pm    = packageManager
                val flags = PackageManager.GET_PERMISSIONS
                val pkgs  = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                    pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
                else @Suppress("DEPRECATION") pm.getInstalledPackages(flags)

                val am      = getSystemService(ACTIVITY_SERVICE) as android.app.ActivityManager
                val running = am.runningAppProcesses?.flatMap {
                    it.pkgList?.toList() ?: emptyList()
                }?.toSet() ?: emptySet()

                for (pkg in pkgs) {
                    val ai = pkg.applicationInfo ?: continue
                    if (pkg.packageName == packageName) continue
                    val isSystem = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    val isUpdated = (ai.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    // Include system VPN apps (built-in VPN client is system)
                    // but flag user-installed VPN apps as suspicious
                    val perms = pkg.requestedPermissions ?: continue
                    if ("android.permission.BIND_VPN_SERVICE" in perms) {
                        val isRunning = running.contains(pkg.packageName)
                        val name = try { pm.getApplicationLabel(ai).toString() }
                                   catch (_: Exception) { pkg.packageName }
                        if (isRunning) {
                            vpnActive  = true
                            vpnPackage = pkg.packageName
                            vpnAppName = name
                        }
                        vpnApps.add(mapOf(
                            "packageName" to pkg.packageName,
                            "appName"     to name,
                            "isRunning"   to isRunning,
                            "isSystemApp" to isSystem,
                        ))
                    }
                }
            } catch (_: Exception) {}

            result.success(mapOf(
                "isVpnActive"    to vpnActive,
                "vpnPackage"     to vpnPackage,
                "vpnAppName"     to vpnAppName,
                "vpnInterfaces"  to vpnIfaces,
                "installedVpnApps" to vpnApps,
                "vpnAppCount"    to vpnApps.size,
            ))
        } catch (e: Exception) {
            result.success(mapOf("isVpnActive" to false, "vpnAppCount" to 0))
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  FOREGROUND SERVICE CONTROL
    // ═══════════════════════════════════════════════════════════════════════

    private fun handleStartForegroundService(
        call: io.flutter.plugin.common.MethodCall,
        result: MethodChannel.Result
    ) {
        try {
            val intervalMs = (call.argument<Int>("intervalMinutes") ?: 15).toLong() * 60 * 1000L
            val intent = Intent(this, ScanForegroundService::class.java).apply {
                putExtra(ScanForegroundService.EXTRA_INTERVAL_MS, intervalMs)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
            Log.i(TAG, "ScanForegroundService started (interval=${intervalMs/60000}min)")
            result.success(true)
        } catch (e: Exception) {
            Log.e(TAG, "startForegroundService failed", e)
            result.success(false)
        }
    }

    private fun handleStopForegroundService(result: MethodChannel.Result) {
        try {
            // Send ACTION_STOP so the service cancels its own alarm + Handler loop
            // before stopping itself. External stopService() would leave orphaned alarms.
            val stopIntent = Intent(this, ScanForegroundService::class.java).apply {
                action = ScanForegroundService.ACTION_STOP
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(stopIntent)
            } else {
                startService(stopIntent)
            }
            Log.i(TAG, "ScanForegroundService stop requested via ACTION_STOP")
            result.success(true)
        } catch (e: Exception) {
            Log.e(TAG, "stopForegroundService failed", e)
            result.success(false)
        }
    }

    private fun openSettings(action: String) {
        try {
            startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (e: ActivityNotFoundException) {
            try {
                startActivity(
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            } catch (_: ActivityNotFoundException) {
                Log.w(TAG, "openSettings: no activity for $action")
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  PRE-INSTALLATION APK SCANNER  (…/scanner, …/file, …/install, …/progress)
    // ═══════════════════════════════════════════════════════════════════════

    private fun runScan(apkPath: String, result: MethodChannel.Result) {
        scope.launch {
            try {
                val json = withContext(Dispatchers.IO) {
                    val file = File(apkPath)
                    require(file.exists() && file.length() > 0) { "APK not found: $apkPath" }
                    require(isValidApk(file)) { "Not a valid APK file." }

                    val ctx = ApkContext.build(applicationContext, file)
                    val l1 = Layer1SafetyAnalyzer(ctx).analyze()
                    pushProgress(0)
                    val l2 = Layer2PermissionMismatch(ctx).analyze()
                    pushProgress(1)
                    val l3 = Layer3SignatureScanner(ctx, applicationContext).analyze()
                    pushProgress(2)
                    val l4 = Layer4MlClassifier(ctx, applicationContext).analyze()
                    pushProgress(3)

                    DecisionEngine(apkPath, l1, l2, l3, l4).computeVerdict().toString()
                }
                result.success(json)
            } catch (e: Exception) {
                result.error("SCAN_ERROR", e.message ?: "Unknown scan error", null)
            }
        }
    }

    private fun pushProgress(layer: Int) {
        scope.launch { progressSink?.success(mapOf("layerComplete" to layer)) }
    }

    private fun startApkPicker(result: MethodChannel.Result) {
        pendingFilePicker = result
        val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
            type = "*/*"
            putExtra(Intent.EXTRA_MIME_TYPES, arrayOf(APK_MIME, "application/octet-stream"))
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        try {
            @Suppress("DEPRECATION")
            startActivityForResult(Intent.createChooser(intent, "Select APK"), REQUEST_PICK_APK)
        } catch (e: ActivityNotFoundException) {
            pendingFilePicker = null
            result.error("NO_PICKER", "No file picker available on this device.", null)
        }
    }

    private fun launchInstaller(apkPath: String, result: MethodChannel.Result) {
        val file = File(apkPath)
        if (!file.exists() || !isValidApk(file)) {
            result.error("INVALID_APK", "The file to install is missing or not a valid APK.", null)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !packageManager.canRequestPackageInstalls()) {
            try {
                startActivity(
                    Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName")),
                )
            } catch (_: ActivityNotFoundException) { }
            result.error("INSTALL_PERMISSION_REQUIRED", "Allow RAT3 to install unknown apps, then try again.", null)
            return
        }
        val uri: Uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        } else {
            @Suppress("DEPRECATION")
            Uri.fromFile(file)
        }
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, APK_MIME)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            startActivity(intent)
            result.success(null)
        } catch (e: ActivityNotFoundException) {
            result.error("NO_INSTALLER", "No package installer available on this device.", null)
        }
    }

    private fun handleViewIntent(intent: Intent?) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val uri = intent.data ?: return
        val type = intent.type ?: contentResolver.getType(uri) ?: ""
        val looksLikeApk = type.contains("package-archive") ||
            uri.toString().endsWith(".apk", ignoreCase = true)
        if (!looksLikeApk) return
        scope.launch {
            val path = withContext(Dispatchers.IO) { resolveApkUri(uri) } ?: return@launch
            pendingIntentPath = path
            notifyFlutterOfApk(path)
        }
    }

    private fun notifyFlutterOfApk(path: String) {
        fileChannel?.invokeMethod("onIncomingApk", mapOf("apkPath" to path))
    }

    private fun resolveApkUri(uri: Uri): String? = when (uri.scheme) {
        "file" -> uri.path?.let { p ->
            val f = File(p)
            if (f.exists() && isValidApk(f)) f.absolutePath else null
        }
        "content" -> copyContentUriToCache(uri)
        else -> null
    }

    private fun copyContentUriToCache(uri: Uri): String? = try {
        val dir = File(cacheDir, CACHE_SUBDIR).apply { mkdirs() }
        val dest = File(dir, sanitizeApkName(queryDisplayName(uri)))
        val copied = contentResolver.openInputStream(uri)?.use { input ->
            dest.outputStream().use { output -> input.copyTo(output) }
        }
        when {
            copied == null -> null
            isValidApk(dest) -> dest.absolutePath
            else -> { dest.delete(); null }
        }
    } catch (e: Exception) {
        null
    }

    private fun sanitizeApkName(raw: String?): String {
        val base = raw?.substringAfterLast('/')?.substringAfterLast('\\').orEmpty()
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .take(80)
        val stem = base.removeSuffix(".apk").ifBlank { "scan" }
        return "${System.currentTimeMillis()}_$stem.apk"
    }

    private fun queryDisplayName(uri: Uri): String? = try {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            val col = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (col >= 0 && cursor.moveToFirst()) cursor.getString(col) else null
        }
    } catch (e: Exception) {
        null
    }

    private fun isValidApk(file: File): Boolean = try {
        ZipFile(file).use { zip -> zip.getEntry("AndroidManifest.xml") != null }
    } catch (e: Exception) {
        false
    }

}