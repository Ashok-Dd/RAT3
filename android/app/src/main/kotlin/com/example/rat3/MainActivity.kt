package com.example.rat3

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.provider.Settings
import androidx.core.content.FileProvider
import com.example.rat3.scanner.ApkContext
import com.example.rat3.scanner.DecisionEngine
import com.example.rat3.scanner.Layer1SafetyAnalyzer
import com.example.rat3.scanner.Layer2PermissionMismatch
import com.example.rat3.scanner.Layer3SignatureScanner
import com.example.rat3.scanner.Layer4HeuristicModel
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
import java.util.zip.ZipFile

/**
 * Single Android entry point. Owns the four platform channels and orchestrates a scan.
 *
 * Channels (names mirrored in `lib/services/channels.dart`):
 *   MethodChannel  …/scanner   scanApk
 *   MethodChannel  …/file      pickApkFile, getInitialApkPath  (+ pushes onIncomingApk)
 *   MethodChannel  …/install   installApk
 *   EventChannel   …/progress  { "layerComplete": Int }
 */
class MainActivity : FlutterActivity() {

    private companion object {
        const val CH_SCANNER = "com.example.rat3/scanner"
        const val CH_FILE = "com.example.rat3/file"
        const val CH_INSTALL = "com.example.rat3/install"
        const val CH_PROGRESS = "com.example.rat3/progress"
        const val REQUEST_PICK_APK = 1001
        const val APK_MIME = "application/vnd.android.package-archive"
        const val CACHE_SUBDIR = "apk_scan"
    }

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var progressSink: EventChannel.EventSink? = null
    private var pendingFilePicker: MethodChannel.Result? = null
    private var fileChannel: MethodChannel? = null

    /** Resolved APK path from an "Open with RAT3" intent, held until Flutter asks for it. */
    @Volatile
    private var pendingIntentPath: String? = null

    // ── lifecycle ────────────────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleViewIntent(intent)
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
        val result = pendingFilePicker
        pendingFilePicker = null
        val uri = data?.data
        if (resultCode != Activity.RESULT_OK || uri == null) {
            result?.success(null)
            return
        }
        scope.launch {
            val path = withContext(Dispatchers.IO) { resolveApkUri(uri) }
            result?.success(path)
        }
    }

    // ── channels ─────────────────────────────────────────────────────────────────────────

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val messenger = flutterEngine.dartExecutor.binaryMessenger

        MethodChannel(messenger, CH_SCANNER).setMethodCallHandler { call, result ->
            when (call.method) {
                "scanApk" -> {
                    val path = call.argument<String>("apkPath")
                    if (path.isNullOrBlank()) {
                        result.error("INVALID", "apkPath required", null)
                    } else {
                        runScan(path, result)
                    }
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
                    if (path.isNullOrBlank()) {
                        result.error("INVALID", "apkPath required", null)
                    } else {
                        launchInstaller(path, result)
                    }
                }
                else -> result.notImplemented()
            }
        }

        EventChannel(messenger, CH_PROGRESS).setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                progressSink = events
            }

            override fun onCancel(arguments: Any?) {
                progressSink = null
            }
        })

        // Warm-start: an APK intent arrived before Flutter attached its listener.
        pendingIntentPath?.let { notifyFlutterOfApk(it) }
    }

    // ── scan orchestration ───────────────────────────────────────────────────────────────

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
                    val l4 = Layer4HeuristicModel(ctx, l1, l2, l3).analyze()
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

    // ── APK picker ───────────────────────────────────────────────────────────────────────

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

    // ── system installer ─────────────────────────────────────────────────────────────────

    private fun launchInstaller(apkPath: String, result: MethodChannel.Result) {
        val file = File(apkPath)
        if (!file.exists() || !isValidApk(file)) {
            result.error("INVALID_APK", "The file to install is missing or not a valid APK.", null)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            !packageManager.canRequestPackageInstalls()
        ) {
            try {
                startActivity(
                    Intent(
                        Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:$packageName"),
                    ),
                )
            } catch (e: ActivityNotFoundException) {
                // fall through to the error below
            }
            result.error(
                "INSTALL_PERMISSION_REQUIRED",
                "Allow RAT3 to install unknown apps, then try again.",
                null,
            )
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

    // ── "Open with RAT3" intent handling ─────────────────────────────────────────────────

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

    // ── URI resolution (runs on Dispatchers.IO) ──────────────────────────────────────────

    private fun resolveApkUri(uri: Uri): String? {
        return when (uri.scheme) {
            "file" -> uri.path?.let { p ->
                val f = File(p)
                if (f.exists() && isValidApk(f)) f.absolutePath else null
            }

            "content" -> copyContentUriToCache(uri)

            else -> null
        }
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

    /** Strips any path components and unusual characters from a provider-supplied file name. */
    private fun sanitizeApkName(raw: String?): String {
        val base = raw?.substringAfterLast('/')?.substringAfterLast('\\').orEmpty()
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .take(80)
        val stem = base.removeSuffix(".apk").ifBlank { "scan" }
        return "${System.currentTimeMillis()}_$stem.apk"
    }

    private fun queryDisplayName(uri: Uri): String? {
        return try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor ->
                    val col = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (col >= 0 && cursor.moveToFirst()) cursor.getString(col) else null
                }
        } catch (e: Exception) {
            null
        }
    }

    /** Minimal structural check: readable ZIP that contains an AndroidManifest.xml entry. */
    private fun isValidApk(file: File): Boolean = try {
        ZipFile(file).use { zip -> zip.getEntry("AndroidManifest.xml") != null }
    } catch (e: Exception) {
        false
    }
}
