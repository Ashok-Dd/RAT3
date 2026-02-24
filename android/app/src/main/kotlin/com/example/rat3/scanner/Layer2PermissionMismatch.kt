package com.example.rat3.scanner

import org.json.JSONObject
import java.io.File
import java.util.zip.ZipFile

/**
 * Layer 2 — Permission–Function Mismatch Detector
 *
 * Cross-references declared permissions against actual API calls in DEX bytecode.
 * Flags permissions declared with no matching API (over-privilege / obfuscation).
 * Also unconditionally flags known-dangerous APIs (Runtime.exec, DexClassLoader…).
 */
class Layer2PermissionMismatch(private val apkFile: File) {

    companion object {
        private val PERMISSION_API_MAP: Map<String, List<String>> = mapOf(
            "android.permission.SEND_SMS" to listOf(
                "SmsManager;->sendTextMessage",
                "SmsManager;->sendMultipartTextMessage"
            ),
            "android.permission.RECORD_AUDIO" to listOf(
                "MediaRecorder;->setAudioSource",
                "AudioRecord;-><init>"
            ),
            "android.permission.CAMERA" to listOf(
                "CameraManager;->openCamera",
                "Camera;->open",
                "CameraDevice"
            ),
            "android.permission.READ_CONTACTS" to listOf(
                "ContactsContract",
                "CommonDataKinds"
            ),
            "android.permission.ACCESS_FINE_LOCATION" to listOf(
                "LocationManager;->requestLocationUpdates",
                "LocationManager;->getLastKnownLocation",
                "FusedLocationProviderClient",
                "LocationRequest"
            ),
            "android.permission.READ_EXTERNAL_STORAGE" to listOf(
                "Environment;->getExternalStorageDirectory",
                "getExternalFilesDir",
                "MediaStore"
            ),
            "android.permission.READ_PHONE_STATE" to listOf(
                "TelephonyManager;->getDeviceId",
                "TelephonyManager;->getSubscriberId",
                "TelephonyManager;->getImei",
                "TelephonyManager;->getLine1Number"
            ),
            "android.permission.RECEIVE_BOOT_COMPLETED" to listOf(
                "BOOT_COMPLETED",
                "QUICKBOOT_POWERON"
            ),
            "android.permission.READ_SMS" to listOf(
                "Telephony\$Sms",
                "content://sms"
            )
        )

        private val ALWAYS_SUSPICIOUS_APIS: List<Pair<String, String>> = listOf(
            "Runtime;->exec("    to "Runtime.exec() — shell command execution",
            "DexClassLoader"     to "DexClassLoader — dynamic code loading (possible payload injection)",
            "PathClassLoader"    to "PathClassLoader — dynamic class loading",
            "Method;->invoke("  to "Reflection (Method.invoke) — may hide true functionality",
            "ServerSocket"       to "ServerSocket — opens listening port (possible backdoor)",
            "ProcessBuilder"     to "ProcessBuilder — process execution"
        )
    }

    fun analyze(): JSONObject {
        val findings = mutableListOf<JSONObject>()
        var riskScore = 0

        return try {
            val dexContent  = extractDexContent()
            val permissions = extractPermissions()
            var mismatchCount = 0

            for ((permission, apis) in PERMISSION_API_MAP) {
                if (permission !in permissions) continue
                val apiUsed = apis.any { token -> dexContent.contains(token) }
                if (!apiUsed) {
                    mismatchCount++
                    riskScore += 10
                    val shortName = permission.removePrefix("android.permission.")
                    findings += finding(
                        "Mismatch: $shortName declared but no matching API found in DEX. " +
                        "Possible over-privilege or obfuscated usage.",
                        isWarning = true,
                        category = "permission_mismatch"
                    )
                }
            }

            for ((token, description) in ALWAYS_SUSPICIOUS_APIS) {
                if (dexContent.contains(token)) {
                    riskScore += 12
                    findings += finding(
                        "Suspicious API: $description",
                        isWarning = true,
                        category = "suspicious_api"
                    )
                }
            }

            if (findings.none { it.optBoolean("isWarning") }) {
                findings += finding(
                    "Permission–API mapping looks consistent. No mismatches detected. ✓",
                    isWarning = false
                )
            }

            buildLayerJson(
                layerName = "Permission–Function Mismatch",
                riskScore = riskScore,
                findings = findings,
                rawData = JSONObject().apply {
                    put("mismatchCount", mismatchCount)
                    put("permissionsChecked", permissions.size)
                    put("dexSizeKB", (dexContent.length / 1024).coerceAtLeast(0))
                }
            )
        } catch (e: Exception) {
            buildLayerJson(
                layerName = "Permission–Function Mismatch",
                riskScore = 25,
                findings = listOf(finding("DEX analysis error: ${e.message}", isWarning = true)),
                rawData = JSONObject()
            )
        }
    }

    private fun extractDexContent(): String {
        val sb = StringBuilder()
        ZipFile(apkFile).use { zip ->
            zip.entries().asSequence()
                .filter { entry -> entry.name.matches(Regex("""classes\d*\.dex""")) }
                .forEach { entry ->
                    zip.getInputStream(entry).use { stream ->
                        sb.append(stream.readBytes().toString(Charsets.ISO_8859_1))
                    }
                }
        }
        return sb.toString()
    }

    private fun extractPermissions(): Set<String> {
        val found = mutableSetOf<String>()
        ZipFile(apkFile).use { zip ->
            val entry = zip.getEntry("AndroidManifest.xml") ?: return found
            val raw   = zip.getInputStream(entry).readBytes().toString(Charsets.ISO_8859_1)
            for (perm in Layer1SafetyAnalyzer.DANGEROUS_PERMISSIONS + Layer1SafetyAnalyzer.SUSPICIOUS_PERMISSIONS) {
                if (raw.contains(perm.takeLast(22))) found += perm
            }
        }
        return found
    }
}