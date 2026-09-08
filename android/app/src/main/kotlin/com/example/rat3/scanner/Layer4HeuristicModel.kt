package com.example.rat3.scanner

import org.json.JSONObject
import com.example.rat3.scanner.ScannerConfig.Layer4 as Cfg

/**
 * Layer 4 — Heuristic Risk Model.
 *
 * NOT a trained machine-learning classifier. It extracts the 17-feature vector documented in
 * `ml/feature_schema.md` (now populated with real values from [ApkContext] and the Layer 1–3
 * results) and scores it with a transparent weighted rule set in [HeuristicRiskModel].
 *
 * Its job is to catch *feature combinations* that the individual layers do not score on their
 * own — e.g. the SMS + microphone + location + many-dangerous-permissions "spyware triad".
 */
class Layer4HeuristicModel(
    private val ctx: ApkContext,
    private val layer1: JSONObject,
    private val layer2: JSONObject,
    private val layer3: JSONObject,
) {

    fun analyze(): JSONObject {
        val features = buildFeatureVector()
        val result = HeuristicRiskModel.score(features)

        val label = when {
            result.score >= Cfg.LABEL_ELEVATED -> "ELEVATED RISK"
            result.score >= Cfg.LABEL_MODERATE -> "MODERATE RISK"
            else -> "LOW RISK"
        }

        val findings = mutableListOf(
            finding(
                "Heuristic risk model: $label (weighted score ${result.score}/100).",
                isWarning = result.score >= Cfg.LABEL_MODERATE,
                category = "heuristic_result",
            ),
        )
        result.reasons.forEach { findings += finding(it, isWarning = true, category = "heuristic_reason") }
        findings += finding(
            "This layer is a transparent rule-weighted heuristic, not a trained ML model.",
            isWarning = false,
            category = "info",
        )

        return buildLayerJson(
            layerName = "Heuristic Risk Model",
            riskScore = result.score,
            findings = findings,
            rawData = JSONObject().apply {
                put("label", label)
                put("featureCount", features.size)
                put("modelType", "weighted-heuristic-v2")
            },
        )
    }

    private fun buildFeatureVector(): FloatArray {
        val perms = ctx.permissions
        val dangerous = perms.count { it in KnownPermissions.DANGEROUS }
        val suspicious = perms.count { it in KnownPermissions.SUSPICIOUS }

        val resourceText = ctx.scanText.removePrefix(ctx.dexText)
        val base64Blobs = Regex("[A-Za-z0-9+/]{400,}={0,2}").findAll(resourceText).count()
        val hasRawIps = layerHasCategory(layer3, "network")
        val hasObfuscation = layerHasCategory(layer3, "obfuscation")

        return floatArrayOf(
            perms.size.toFloat(),                                              // 0  numPermissions
            dangerous.toFloat(),                                               // 1  numDangerousPermissions
            suspicious.toFloat(),                                              // 2  numSuspiciousPermissions
            ctx.exportedComponentCount.toFloat(),                              // 3  numExportedComponents
            ctx.targetSdk.toFloat(),                                           // 4  targetSdk
            bool(perms.any { it.contains("SMS") }),                            // 5  hasSmsPermission
            bool(perms.contains("android.permission.CAMERA")),                 // 6  hasCameraPermission
            bool(perms.any { it.contains("LOCATION") }),                       // 7  hasLocationPermission
            bool(perms.contains("android.permission.RECORD_AUDIO")),           // 8  hasAudioPermission
            ctx.nativeLibs.size.toFloat(),                                     // 9  numNativeLibs
            bool(hasObfuscation),                                              // 10 hasObfuscation
            (ctx.dexText.length / 1024).toFloat(),                             // 11 dexSizeKB
            base64Blobs.toFloat(),                                             // 12 numBase64Blobs
            bool(hasRawIps),                                                   // 13 hasRawIpAddresses
            layer1.optInt("riskScore").toFloat(),                             // 14 layer1RiskScore
            layer2.optInt("riskScore").toFloat(),                             // 15 layer2RiskScore
            layer3.optInt("riskScore").toFloat(),                             // 16 layer3RiskScore
        )
    }

    private fun bool(b: Boolean): Float = if (b) 1f else 0f

    private fun layerHasCategory(layer: JSONObject, category: String): Boolean {
        val findings = layer.optJSONArray("findings") ?: return false
        for (i in 0 until findings.length()) {
            if (findings.optJSONObject(i)?.optString("category") == category) return true
        }
        return false
    }
}

/** Transparent weighted rule set used by [Layer4HeuristicModel]. */
object HeuristicRiskModel {

    data class Result(val score: Int, val reasons: List<String>)

    /** Feature vector layout matches `ml/feature_schema.md`. */
    fun score(f: FloatArray): Result {
        val numDangerous = f.getOrElse(1) { 0f }
        val numSuspicious = f.getOrElse(2) { 0f }
        val hasSms = f.getOrElse(5) { 0f } == 1f
        val hasLocation = f.getOrElse(7) { 0f } == 1f
        val hasAudio = f.getOrElse(8) { 0f } == 1f
        val numNativeLibs = f.getOrElse(9) { 0f }
        val hasObfuscation = f.getOrElse(10) { 0f } == 1f
        val dexSizeKB = f.getOrElse(11) { 0f }
        val numBase64 = f.getOrElse(12) { 0f }
        val hasRawIps = f.getOrElse(13) { 0f } == 1f
        val priorMean = (f.getOrElse(14) { 0f } + f.getOrElse(15) { 0f } + f.getOrElse(16) { 0f }) / 3f

        var score = priorMean * Cfg.PRIOR_LAYER_PULL.toFloat()
        val reasons = mutableListOf<String>()

        if (hasSms && hasAudio && hasLocation && numDangerous >= 6f) {
            score += Cfg.SPYWARE_TRIAD_POINTS
            reasons += "SMS + microphone + location + broad permissions — classic spyware capability set."
        }
        if (hasRawIps && hasObfuscation) {
            score += Cfg.OBFUSCATED_C2_POINTS
            reasons += "Hardcoded network endpoints together with obfuscated payload data."
        }
        if (dexSizeKB > 8000f && numBase64 >= 8f && numNativeLibs > 0f) {
            score += Cfg.HEAVY_PAYLOAD_POINTS
            reasons += "Large code base with many encoded blobs and native libraries."
        }
        if (hasSms && numSuspicious >= 2f) {
            score += Cfg.SMS_PLUS_SUSPICIOUS_POINTS
            reasons += "SMS access combined with multiple rarely-legitimate permissions."
        }

        return Result(score.toInt().coerceIn(0, 100), reasons)
    }
}
