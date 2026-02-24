package com.example.rat3

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.core.content.FileProvider
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
import com.example.rat3.scanner.DecisionEngine
import com.example.rat3.scanner.Layer1SafetyAnalyzer
import com.example.rat3.scanner.Layer2PermissionMismatch
import com.example.rat3.scanner.Layer3SignatureScanner
import com.example.rat3.scanner.Layer4MLScanner

class MainActivity : FlutterActivity() {

    companion object {
        private const val CH_SCANNER       = "com.example.rat3/scanner"
        private const val CH_FILE          = "com.example.rat3/file"
        private const val CH_INSTALL       = "com.example.rat3/install"
        private const val CH_PROGRESS      = "com.example.rat3/progress"
        private const val REQUEST_PICK_APK = 1001
    }

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var progressSink: EventChannel.EventSink? = null
    private var pendingFileResult: MethodChannel.Result? = null

    // APK path from "Open with RAT3" intent — stored here until Flutter is ready
    private var pendingIntentPath: String? = null

    // ── Lifecycle ──────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Extract APK path from the intent that launched us
        handleViewIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // App was already running; send directly to Flutter
        handleViewIntent(intent)
    }

    @Deprecated("Using onActivityResult for FlutterActivity compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_PICK_APK) {
            val path = if (resultCode == Activity.RESULT_OK) {
                data?.data?.let { resolveUri(it) }
            } else null
            pendingFileResult?.success(path)
            pendingFileResult = null
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }

    // ── Flutter Engine ─────────────────────────────────────────────────

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val m = flutterEngine.dartExecutor.binaryMessenger

        // ── Scanner channel ────────────────────────────────────────────
        MethodChannel(m, CH_SCANNER).setMethodCallHandler { call, result ->
            when (call.method) {
                "scanApk" -> {
                    val path = call.argument<String>("apkPath")
                    if (path.isNullOrBlank()) result.error("INVALID", "apkPath required", null)
                    else runScan(path, result)
                }
                else -> result.notImplemented()
            }
        }

        // ── File channel ───────────────────────────────────────────────
        MethodChannel(m, CH_FILE).setMethodCallHandler { call, result ->
            when (call.method) {
                "pickApkFile" -> {
                    pendingFileResult = result
                    val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                        type = "application/vnd.android.package-archive"
                        addCategory(Intent.CATEGORY_OPENABLE)
                    }
                    @Suppress("DEPRECATION")
                    startActivityForResult(
                        Intent.createChooser(intent, "Select APK"),
                        REQUEST_PICK_APK
                    )
                }

                // Flutter (SplashScreen) asks: "was there an APK in the launch intent?"
                // This covers the cold-start case before our MethodChannel listener was set.
                "getInitialApkPath" -> {
                    result.success(pendingIntentPath)
                    // Don't clear it here — main.dart and splash_screen both query this
                }

                else -> result.notImplemented()
            }
        }

        // ── Install channel ────────────────────────────────────────────
        MethodChannel(m, CH_INSTALL).setMethodCallHandler { call, result ->
            when (call.method) {
                "installApk" -> {
                    val path = call.argument<String>("apkPath")
                    if (path.isNullOrBlank()) result.error("INVALID", "apkPath required", null)
                    else { launchInstaller(path); result.success(null) }
                }
                else -> result.notImplemented()
            }
        }

        // ── Progress EventChannel ──────────────────────────────────────
        EventChannel(m, CH_PROGRESS).setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                progressSink = events
            }
            override fun onCancel(arguments: Any?) {
                progressSink = null
            }
        })

        // ── Forward pending APK to Flutter (warm-start or race condition) ──
        pendingIntentPath?.let { path ->
            // Don't clear — SplashScreen may also query via getInitialApkPath
            MethodChannel(m, CH_FILE).invokeMethod("onIncomingApk", mapOf("apkPath" to path))
        }
    }

    // ── Scan orchestration ─────────────────────────────────────────────

    private fun runScan(apkPath: String, result: MethodChannel.Result) {
        scope.launch {
            try {
                val json = withContext(Dispatchers.IO) {
                    val file = File(apkPath)
                    check(file.exists() && file.length() > 0) { "APK not found: $apkPath" }

                    val l1 = Layer1SafetyAnalyzer(file).analyze()
                    pushProgress(0)
                    val l2 = Layer2PermissionMismatch(file).analyze()
                    pushProgress(1)
                    val l3 = Layer3SignatureScanner(file, applicationContext).analyze()
                    pushProgress(2)
                    val l4 = Layer4MLScanner(file, applicationContext).analyze()
                    pushProgress(3)

                    DecisionEngine(apkPath, l1, l2, l3, l4).computeVerdict().toString()
                }
                result.success(json)
            } catch (e: Exception) {
                result.error("SCAN_ERROR", e.message ?: "Unknown error", null)
            }
        }
    }

    private fun pushProgress(layer: Int) {
        scope.launch(Dispatchers.Main) {
            progressSink?.success(mapOf("layerComplete" to layer))
        }
    }

    // ── System installer ───────────────────────────────────────────────

    private fun launchInstaller(apkPath: String) {
        val file = File(apkPath)
        val uri: Uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            FileProvider.getUriForFile(this, "${packageName}.fileprovider", file)
        } else {
            @Suppress("DEPRECATION")
            Uri.fromFile(file)
        }
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try { startActivity(intent) } catch (e: ActivityNotFoundException) { }
    }

    // ── "Open with RAT3" intent handling ──────────────────────────────

    /**
     * Called on cold-start and warm-start (onNewIntent).
     *
     * Cold-start: Flutter isn't ready yet.
     *   → Store path in [pendingIntentPath].
     *   → SplashScreen calls getInitialApkPath() to retrieve it.
     *   → configureFlutterEngine also calls onIncomingApk for safety.
     *
     * Warm-start (onNewIntent): Flutter IS ready.
     *   → Call onIncomingApk directly via MethodChannel.
     *   → main.dart listener or home_screen listener handles navigation.
     */
    private fun handleViewIntent(intent: Intent?) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val uri = intent.data ?: return
        val type = intent.type ?: contentResolver.getType(uri) ?: return
        if (!type.contains("android.package-archive")) return

        val path = resolveUri(uri) ?: return
        pendingIntentPath = path

        // If engine is already up (warm-start), push immediately
        flutterEngine?.let { engine ->
            MethodChannel(engine.dartExecutor.binaryMessenger, CH_FILE)
                .invokeMethod("onIncomingApk", mapOf("apkPath" to path))
        }
    }

    // ── URI resolution ─────────────────────────────────────────────────

    private fun resolveUri(uri: Uri): String? = when (uri.scheme) {
        "file" -> uri.path
        "content" -> try {
            val name = getDisplayName(uri) ?: "rat3_scan_${System.currentTimeMillis()}.apk"
            val dest = File(cacheDir, name)
            contentResolver.openInputStream(uri)?.use { input ->
                dest.outputStream().use { output -> input.copyTo(output) }
            }
            dest.absolutePath
        } catch (e: Exception) { null }
        else -> null
    }

    private fun getDisplayName(uri: Uri): String? {
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val col = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (col >= 0 && cursor.moveToFirst()) return cursor.getString(col)
        }
        return null
    }
}