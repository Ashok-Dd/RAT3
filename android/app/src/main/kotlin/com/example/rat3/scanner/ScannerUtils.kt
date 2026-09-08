package com.example.rat3.scanner

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

/**
 * Shared helpers used by all four scanner layers: JSON result building, logging, and the
 * canonical Android permission lists.
 */

private const val LOG_TAG = "RAT3.scanner"

/** Single logging entry point so layer failures are always recorded (never silently swallowed). */
object ScanLog {
    fun w(where: String, t: Throwable) {
        Log.w(LOG_TAG, "$where: ${t.javaClass.simpleName}: ${t.message}", t)
    }

    fun w(where: String, message: String) {
        Log.w(LOG_TAG, "$where: $message")
    }
}

/**
 * Builds a single finding object shown in the UI.
 *
 * @param message   human-readable description
 * @param isWarning true renders a warning icon; false an info icon
 * @param category  optional machine-readable tag (e.g. "network", "obfuscation")
 */
fun finding(
    message: String,
    isWarning: Boolean,
    category: String? = null,
): JSONObject = JSONObject().apply {
    put("message", message)
    put("isWarning", isWarning)
    category?.let { put("category", it) }
}

/**
 * Builds the standard layer-result object returned to Flutter (schema mirrors the Dart
 * `LayerResult` model). Risk score is clamped to 0..100 here so layers can add points freely.
 *
 * @param analysisError set true when the layer could not complete; the decision engine then
 *        limits how much this layer's score can affect the final verdict.
 */
fun buildLayerJson(
    layerName: String,
    riskScore: Int,
    findings: List<JSONObject>,
    rawData: JSONObject = JSONObject(),
    analysisError: Boolean = false,
): JSONObject = JSONObject().apply {
    put("layerName", layerName)
    put("riskScore", riskScore.coerceIn(0, 100))
    put("findings", JSONArray(findings))
    put("rawData", rawData.apply { put("analysisError", analysisError) })
}

/**
 * Canonical Android permission classification, shared by every layer so there is exactly one
 * source of truth (previously each layer used ad-hoc `takeLast(n)` substring hacks).
 */
object KnownPermissions {

    val DANGEROUS: Set<String> = setOf(
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.GET_ACCOUNTS",
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BLUETOOTH_CONNECT",
    )

    /** Permissions that are legal but rarely needed and heavily abused by RAT / spyware. */
    val SUSPICIOUS: Set<String> = setOf(
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.MANAGE_ACCOUNTS",
        "android.permission.KILL_BACKGROUND_PROCESSES",
        "android.permission.DISABLE_KEYGUARD",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    )

    fun shortName(permission: String): String = permission.substringAfterLast('.')
}
