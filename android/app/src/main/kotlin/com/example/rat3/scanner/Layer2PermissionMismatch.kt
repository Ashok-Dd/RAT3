package com.example.rat3.scanner

import org.json.JSONObject
import com.example.rat3.scanner.ScannerConfig.Layer2 as Cfg

/**
 * Layer 2 — Permission ↔ Function Mismatch.
 *
 * Two low-to-moderate confidence checks against the (bounded) DEX text in [ApkContext]:
 *  1. A declared permission with no matching API token in the DEX — possible over-privilege or
 *     reflection-hidden usage. Deliberately low weight: libraries and future-use permissions
 *     make this noisy.
 *  2. A short list of APIs that are genuinely dangerous regardless of context
 *     (shell execution, dynamic code loading, raw sockets).
 *
 * `PathClassLoader` and bare `Method.invoke` were removed from that list — they appear in
 * essentially every modern APK (Kotlin reflection, AndroidX) and only produced false positives.
 */
class Layer2PermissionMismatch(private val ctx: ApkContext) {

    private companion object {
        val PERMISSION_API_MAP: Map<String, List<String>> = mapOf(
            "android.permission.SEND_SMS" to listOf(
                "SmsManager;->sendTextMessage", "SmsManager;->sendMultipartTextMessage",
            ),
            "android.permission.RECORD_AUDIO" to listOf(
                "MediaRecorder;->setAudioSource", "AudioRecord;-><init>",
            ),
            "android.permission.CAMERA" to listOf(
                "CameraManager;->openCamera", "Camera;->open", "Landroid/hardware/camera2/",
            ),
            "android.permission.READ_CONTACTS" to listOf(
                "ContactsContract", "content://com.android.contacts",
            ),
            "android.permission.ACCESS_FINE_LOCATION" to listOf(
                "LocationManager;->requestLocationUpdates",
                "LocationManager;->getLastKnownLocation",
                "FusedLocationProviderClient",
            ),
            "android.permission.READ_PHONE_STATE" to listOf(
                "TelephonyManager;->getDeviceId", "TelephonyManager;->getSubscriberId",
                "TelephonyManager;->getImei", "TelephonyManager;->getLine1Number",
            ),
            "android.permission.READ_SMS" to listOf(
                "content://sms", "Telephony\$Sms",
            ),
            "android.permission.READ_CALL_LOG" to listOf(
                "content://call_log", "CallLog\$Calls",
            ),
        )

        val DANGEROUS_APIS: List<Triple<String, String, Int>> = listOf(
            Triple("Runtime;->exec(", "Runtime.exec() — shell command execution",
                Cfg.API_RUNTIME_EXEC_POINTS),
            Triple("Ldalvik/system/DexClassLoader", "DexClassLoader — loads code at runtime (payload staging)",
                Cfg.API_DEX_CLASSLOADER_POINTS),
            Triple("Ljava/lang/ProcessBuilder", "ProcessBuilder — spawns external processes",
                Cfg.API_PROCESS_BUILDER_POINTS),
            Triple("Ljava/net/ServerSocket", "ServerSocket — opens a listening port (possible backdoor)",
                Cfg.API_SERVER_SOCKET_POINTS),
        )
    }

    fun analyze(): JSONObject {
        val findings = mutableListOf<JSONObject>()
        var score = 0
        var mismatches = 0

        for ((permission, apis) in PERMISSION_API_MAP) {
            if (permission !in ctx.permissions) continue
            if (apis.none { ctx.dexText.contains(it) }) {
                mismatches++
                score += Cfg.MISMATCH_POINTS
                findings += finding(
                    "${KnownPermissions.shortName(permission)} is declared but no matching API " +
                        "was found in the code (low confidence — could be reflection or unused).",
                    isWarning = true,
                    category = "permission_mismatch",
                )
            }
        }
        score = minOf(score, Cfg.MISMATCH_CAP)

        for ((token, description, points) in DANGEROUS_APIS) {
            if (ctx.dexText.contains(token)) {
                score += points
                findings += finding("Dangerous API: $description", isWarning = true, category = "dangerous_api")
            }
        }

        if (ctx.dexTruncated) {
            findings += finding(
                "Code was large and only partially scanned — some APIs may be missed.",
                isWarning = false,
                category = "info",
            )
        }
        if (findings.none { it.optBoolean("isWarning") }) {
            findings += finding("Permissions and code usage look consistent.", isWarning = false)
        }

        return buildLayerJson(
            layerName = "Permission–Function Mismatch",
            riskScore = score,
            findings = findings,
            rawData = JSONObject().apply {
                put("mismatchCount", mismatches)
                put("permissionsChecked", ctx.permissions.size)
                put("dexTruncated", ctx.dexTruncated)
            },
        )
    }
}
