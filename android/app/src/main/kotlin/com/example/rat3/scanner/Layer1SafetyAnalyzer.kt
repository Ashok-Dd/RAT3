package com.example.rat3.scanner

import org.json.JSONObject
import java.io.File
import java.util.zip.ZipFile

/**
 * Layer 1 — App Safety Analysis (Rule-Based)
 *
 * Parses the binary AndroidManifest.xml (AXML format) from the APK ZIP and scores:
 *   • Dangerous permissions declared
 *   • Suspicious permissions (rarely needed by legitimate apps)
 *   • Exported components accessible by other apps
 *   • Target / minimum SDK version
 */
class Layer1SafetyAnalyzer(private val apkFile: File) {

    companion object {
        val DANGEROUS_PERMISSIONS: Set<String> = setOf(
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.CALL_PHONE",
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
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FINGERPRINT",
            "android.permission.BODY_SENSORS",
            "android.permission.ACTIVITY_RECOGNITION",
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.BLUETOOTH_CONNECT",
        )

        val SUSPICIOUS_PERMISSIONS: Set<String> = setOf(
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.WRITE_SETTINGS",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.MANAGE_ACCOUNTS",
            "android.permission.KILL_BACKGROUND_PROCESSES",
            "android.permission.DISABLE_KEYGUARD",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.SET_WALLPAPER",
        )
    }

    fun analyze(): JSONObject {
        val findings = mutableListOf<JSONObject>()
        var riskScore = 0

        return try {
            val manifestBytes = readManifestBytes()
            val parsed = AXmlParser(manifestBytes).parse()

            val dangerCount = parsed.permissions.count { it in DANGEROUS_PERMISSIONS }
            riskScore += minOf(dangerCount * 5, 40)

            val suspiciousFound = parsed.permissions.filter { it in SUSPICIOUS_PERMISSIONS }
            riskScore += minOf(suspiciousFound.size * 8, 25)

            if (parsed.exportedComponents > 0) {
                riskScore += minOf(parsed.exportedComponents * 3, 20)
                findings += finding(
                    "${parsed.exportedComponents} exported component(s) found. " +
                    "Can be invoked by third-party apps.",
                    isWarning = parsed.exportedComponents > 2,
                    category = "exported_components"
                )
            }

            if (parsed.targetSdk in 1 until 28) {
                riskScore += 15
                findings += finding(
                    "Targets old API level ${parsed.targetSdk} (pre-Android 9). " +
                    "May bypass modern OS security restrictions.",
                    isWarning = true,
                    category = "sdk_version"
                )
            } else if (parsed.targetSdk >= 28) {
                findings += finding(
                    "Targets API ${parsed.targetSdk} — modern SDK. ✓",
                    isWarning = false,
                    category = "sdk_version"
                )
            }

            parsed.permissions.filter { it in DANGEROUS_PERMISSIONS }.forEach { perm ->
                val shortName = perm.removePrefix("android.permission.")
                findings += finding(
                    "Dangerous permission: $shortName",
                    isWarning = perm.contains("SMS") || perm.contains("LOCATION"),
                    category = "dangerous_permission"
                )
            }

            suspiciousFound.forEach { perm ->
                val shortName = perm.removePrefix("android.permission.")
                findings += finding(
                    "Suspicious permission: $shortName — rarely needed by legitimate apps.",
                    isWarning = true,
                    category = "suspicious_permission"
                )
            }

            if (parsed.permissions.size > 20) {
                riskScore += 10
                findings += finding(
                    "Declares ${parsed.permissions.size} permissions — unusually large set.",
                    isWarning = true,
                    category = "over_privilege"
                )
            }

            buildLayerJson(
                layerName = "App Safety Analysis",
                riskScore = riskScore,
                findings = findings,
                rawData = JSONObject().apply {
                    put("permissionCount", parsed.permissions.size)
                    put("dangerousPermissionCount", dangerCount)
                    put("suspiciousPermissionCount", suspiciousFound.size)
                    put("exportedComponents", parsed.exportedComponents)
                    put("targetSdk", parsed.targetSdk)
                    put("minSdk", parsed.minSdk)
                }
            )
        } catch (e: Exception) {
            buildLayerJson(
                layerName = "App Safety Analysis",
                riskScore = 50,
                findings = listOf(finding("Manifest parse failed: ${e.message}", isWarning = true)),
                rawData = JSONObject()
            )
        }
    }

    private fun readManifestBytes(): ByteArray {
        ZipFile(apkFile).use { zip ->
            val entry = zip.getEntry("AndroidManifest.xml")
                ?: throw IllegalStateException("AndroidManifest.xml missing from APK")
            return zip.getInputStream(entry).readBytes()
        }
    }
}

// ── Manifest parse result ──────────────────────────────────────────────────

data class ManifestData(
    val permissions: List<String>,
    val exportedComponents: Int,
    val targetSdk: Int,
    val minSdk: Int,
)

// ── AXML Binary Manifest Parser ────────────────────────────────────────────

class AXmlParser(private val data: ByteArray) {

    private companion object {
        const val RES_STRING_POOL_TYPE       = 0x0001
        const val RES_XML_START_ELEMENT_TYPE = 0x0102
    }

    private val strings = mutableListOf<String>()

    init {
        parseStringPool()
    }

    fun parse(): ManifestData {
        val permissions        = mutableListOf<String>()
        var exportedComponents = 0
        var targetSdk          = 0
        var minSdk             = 0

        try {
            var pos = findFirstXmlChunk()
            while (pos + 8 <= data.size) {
                val chunkType = readU16(pos)
                val chunkSize = readU32(pos + 4)
                if (chunkSize <= 0 || pos + chunkSize > data.size) break

                if (chunkType == RES_XML_START_ELEMENT_TYPE) {
                    val (name, attrs) = readStartElement(pos)
                    when (name) {
                        "uses-permission", "uses-permission-sdk-23" -> {
                            attrs["name"]?.let { permissions += it }
                        }
                        "uses-sdk" -> {
                            attrs["targetSdkVersion"]?.toIntOrNull()?.let { targetSdk = it }
                            attrs["minSdkVersion"]?.toIntOrNull()?.let { minSdk = it }
                        }
                        "activity", "service", "receiver", "provider" -> {
                            val exported = attrs["exported"]
                            if (exported == "true" || exported == "-1") exportedComponents++
                        }
                    }
                }
                pos += chunkSize
            }
        } catch (e: Exception) {
            // Fallback: raw byte scan for permission strings
            val raw = String(data, Charsets.ISO_8859_1)
            for (perm in Layer1SafetyAnalyzer.DANGEROUS_PERMISSIONS) {
                if (raw.contains(perm.takeLast(20))) permissions += perm
            }
        }

        return ManifestData(permissions, exportedComponents, targetSdk, minSdk)
    }

    private fun parseStringPool() {
        if (data.size < 8) return
        var pos = 8
        if (pos + 8 > data.size) return

        val chunkType = readU16(pos)
        if (chunkType != RES_STRING_POOL_TYPE) return

        val chunkSize    = readU32(pos + 4)
        val strCount     = readU32(pos + 8)
        val flags        = readU32(pos + 16)
        val stringsStart = readU32(pos + 20)
        val offsetBase   = pos + 28
        val stringBase   = pos + stringsStart
        val isUtf8       = (flags and 0x100) != 0

        for (i in 0 until strCount) {
            val offPos = offsetBase + i * 4
            if (offPos + 4 > data.size) break
            val off = stringBase + readU32(offPos)
            strings += if (isUtf8) readUtf8String(off) else readUtf16String(off)
        }
    }

    private fun readUtf8String(off: Int): String {
        if (off + 2 > data.size) return ""
        val byteLen = data[off + 1].toInt() and 0xFF
        val start   = off + 2
        return if (start + byteLen <= data.size)
            String(data, start, byteLen, Charsets.UTF_8) else ""
    }

    private fun readUtf16String(off: Int): String {
        if (off + 2 > data.size) return ""
        val charLen = readU16(off)
        val start   = off + 2
        val byteLen = charLen * 2
        return if (start + byteLen <= data.size)
            String(data, start, byteLen, Charsets.UTF_16LE) else ""
    }

    private fun findFirstXmlChunk(): Int {
        var pos = 8
        while (pos + 8 <= data.size) {
            val type = readU16(pos)
            val size = readU32(pos + 4)
            if (size <= 0) break
            if (type == RES_XML_START_ELEMENT_TYPE) return pos
            pos += size
        }
        return pos
    }

    private fun readStartElement(base: Int): Pair<String, Map<String, String>> {
        val nameRef   = readU32(base + 20)
        val name      = strings.getOrElse(nameRef) { "" }
        val attrCount = readU16(base + 28)
        val attrSize  = readU16(base + 26).let { if (it == 0) 20 else it }
        val attrs     = mutableMapOf<String, String>()
        var attrPos   = base + 36

        repeat(attrCount) {
            if (attrPos + attrSize <= data.size) {
                val attrNameRef = readU32(attrPos + 4)
                val dataType    = data[attrPos + 15].toInt() and 0xFF
                val dataVal     = readU32(attrPos + 16)
                val attrName    = strings.getOrElse(attrNameRef) { "" }
                val value = when (dataType) {
                    0x03 -> strings.getOrElse(dataVal) { "" }
                    0x10 -> dataVal.toString()
                    0x11 -> dataVal.toString()
                    0x12 -> if (dataVal != 0) "true" else "false"
                    else -> dataVal.toString()
                }
                if (attrName.isNotEmpty()) attrs[attrName] = value
            }
            attrPos += attrSize
        }
        return name to attrs
    }

    private fun readU16(pos: Int): Int {
        if (pos + 2 > data.size) return 0
        return (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)
    }

    private fun readU32(pos: Int): Int {
        if (pos + 4 > data.size) return 0
        return  (data[pos].toInt()     and 0xFF)        or
                ((data[pos + 1].toInt() and 0xFF) shl 8)  or
                ((data[pos + 2].toInt() and 0xFF) shl 16) or
                ((data[pos + 3].toInt() and 0xFF) shl 24)
    }
}