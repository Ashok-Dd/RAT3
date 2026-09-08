package com.example.rat3.scanner

import org.json.JSONObject
import com.example.rat3.scanner.ScannerConfig.Layer1 as Cfg

/**
 * Layer 1 — App Safety Analysis (rule-based).
 *
 * Reads the manifest facts already parsed into [ApkContext] and scores:
 *  - dangerous / suspicious permissions
 *  - exported components beyond a normal allowance
 *  - old / unknown target SDK
 *  - accessibility-service abuse (the RAT / banker fingerprint)
 *  - a DeviceAdmin receiver (persistence / remote lock-wipe)
 */
class Layer1SafetyAnalyzer(private val ctx: ApkContext) {

    fun analyze(): JSONObject {
        val findings = mutableListOf<JSONObject>()
        var score = 0

        val dangerous = ctx.permissions.filter { it in KnownPermissions.DANGEROUS }
        val suspicious = ctx.permissions.filter { it in KnownPermissions.SUSPICIOUS }

        score += scorePermissions(dangerous, suspicious, findings)
        score += scoreExportedComponents(findings)
        score += scoreTargetSdk(findings)
        score += scoreAccessibility(findings)
        score += scoreDeviceAdmin(findings)

        if (ctx.manifestParseFailed) {
            findings += finding(
                "Manifest could not be fully parsed — results for this layer are limited.",
                isWarning = true,
                category = "parse_error",
            )
        }
        if (findings.none { it.optBoolean("isWarning") }) {
            findings += finding("No high-risk manifest characteristics found.", isWarning = false)
        }

        return buildLayerJson(
            layerName = "App Safety Analysis",
            riskScore = score,
            findings = findings,
            rawData = JSONObject().apply {
                put("permissionCount", ctx.permissions.size)
                put("dangerousPermissionCount", dangerous.size)
                put("suspiciousPermissionCount", suspicious.size)
                put("exportedComponents", ctx.exportedComponentCount)
                put("targetSdk", ctx.targetSdk)
                put("minSdk", ctx.minSdk)
                put("accessibilityAbuse", ctx.accessibility.isAbusive)
                put("deviceAdmin", ctx.hasDeviceAdminReceiver)
            },
            analysisError = ctx.manifestParseFailed,
        )
    }

    private fun scorePermissions(
        dangerous: List<String>,
        suspicious: List<String>,
        findings: MutableList<JSONObject>,
    ): Int {
        var score = minOf(dangerous.size * Cfg.DANGEROUS_PERM_POINTS, Cfg.DANGEROUS_PERM_CAP)
        score += minOf(suspicious.size * Cfg.SUSPICIOUS_PERM_POINTS, Cfg.SUSPICIOUS_PERM_CAP)

        dangerous.forEach { perm ->
            val name = KnownPermissions.shortName(perm)
            findings += finding(
                "Dangerous permission: $name",
                isWarning = perm.contains("SMS") || perm.contains("CALL") ||
                    perm.contains("RECORD_AUDIO") || perm.contains("LOCATION"),
                category = "dangerous_permission",
            )
        }
        suspicious.forEach { perm ->
            findings += finding(
                "Rarely-legitimate permission: ${KnownPermissions.shortName(perm)}",
                isWarning = true,
                category = "suspicious_permission",
            )
        }
        if (ctx.permissions.size > Cfg.MANY_PERMISSIONS_THRESHOLD) {
            score += Cfg.MANY_PERMISSIONS_POINTS
            findings += finding(
                "Declares ${ctx.permissions.size} permissions — unusually large set.",
                isWarning = true,
                category = "over_privilege",
            )
        }
        return score
    }

    private fun scoreExportedComponents(findings: MutableList<JSONObject>): Int {
        val extra = ctx.exportedComponentCount - Cfg.EXPORTED_FREE_ALLOWANCE
        if (extra <= 0) return 0
        val score = minOf(extra * Cfg.EXPORTED_POINTS_PER_EXTRA, Cfg.EXPORTED_CAP)
        findings += finding(
            "${ctx.exportedComponentCount} exported components — more than typical; " +
                "some may be invocable by other apps.",
            isWarning = ctx.exportedComponentCount > Cfg.EXPORTED_FREE_ALLOWANCE + 4,
            category = "exported_components",
        )
        return score
    }

    private fun scoreTargetSdk(findings: MutableList<JSONObject>): Int = when {
        ctx.targetSdk == 0 -> {
            findings += finding(
                "Could not determine target SDK version.",
                isWarning = true,
                category = "sdk_version",
            )
            Cfg.TARGET_SDK_UNKNOWN_POINTS
        }
        ctx.targetSdk < Cfg.TARGET_SDK_VERY_OLD -> {
            findings += finding(
                "Targets very old API ${ctx.targetSdk} (pre-runtime-permissions) — " +
                    "can sidestep modern OS restrictions.",
                isWarning = true,
                category = "sdk_version",
            )
            Cfg.TARGET_SDK_VERY_OLD_POINTS
        }
        ctx.targetSdk < Cfg.TARGET_SDK_OLD -> {
            findings += finding(
                "Targets old API ${ctx.targetSdk} (pre-Android 9).",
                isWarning = true,
                category = "sdk_version",
            )
            Cfg.TARGET_SDK_OLD_POINTS
        }
        else -> {
            findings += finding(
                "Targets API ${ctx.targetSdk} — modern SDK.",
                isWarning = false,
                category = "sdk_version",
            )
            0
        }
    }

    private fun scoreAccessibility(findings: MutableList<JSONObject>): Int {
        val a = ctx.accessibility
        if (!a.declaresService) return 0
        var score = 0
        if (a.canRetrieveWindowContent) {
            score += Cfg.ACCESSIBILITY_RETRIEVE_CONTENT_POINTS
            findings += finding(
                "Accessibility service can read on-screen content of every app — " +
                    "a common keylogging / overlay technique.",
                isWarning = true,
                category = "accessibility",
            )
        }
        if (a.canPerformGestures) {
            score += Cfg.ACCESSIBILITY_PERFORM_GESTURES_POINTS
            findings += finding(
                "Accessibility service can perform taps/swipes on the user's behalf.",
                isWarning = true,
                category = "accessibility",
            )
        }
        val persistence = ctx.hasPermission("android.permission.SYSTEM_ALERT_WINDOW") ||
            ctx.hasPermission("android.permission.RECEIVE_BOOT_COMPLETED")
        if (a.isAbusive && persistence) {
            score += Cfg.ACCESSIBILITY_PERSISTENCE_COMBO_POINTS
            findings += finding(
                "Accessibility abuse combined with overlay / boot-persistence — " +
                    "strong RAT / banking-trojan indicator.",
                isWarning = true,
                category = "accessibility",
            )
        }
        return score
    }

    private fun scoreDeviceAdmin(findings: MutableList<JSONObject>): Int {
        if (!ctx.hasDeviceAdminReceiver) return 0
        findings += finding(
            "Declares a Device Administrator receiver — can enforce lock/wipe policies and " +
                "resist uninstallation.",
            isWarning = true,
            category = "device_admin",
        )
        return Cfg.DEVICE_ADMIN_POINTS
    }
}
