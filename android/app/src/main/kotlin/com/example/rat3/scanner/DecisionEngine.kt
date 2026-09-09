package com.example.rat3.scanner

import org.json.JSONObject
import com.example.rat3.scanner.ScannerConfig.Decision as Cfg

/**
 * Fuses the four layer results into one verdict.
 *
 *   weighted = L1·0.20 + L2·0.20 + L3·0.35 + L4·0.25
 *
 * A layer that failed to analyse (`rawData.analysisError == true`) has its contribution capped
 * at [Cfg.ERRORED_LAYER_MAX_CONTRIBUTION] so a parse failure alone can never produce a MALICIOUS
 * verdict. When Layer 3 reports a hard hit (blocklist / signature / repackaging) the score is
 * escalated to at least [Cfg.ESCALATION_MIN_SCORE].
 *
 *   < 30            → SAFE
 *   30 .. 59        → SUSPICIOUS
 *   ≥ 60            → MALICIOUS
 */
class DecisionEngine(
    private val apkPath: String,
    private val layer1: JSONObject,
    private val layer2: JSONObject,
    private val layer3: JSONObject,
    private val layer4: JSONObject,
) {

    fun computeVerdict(): JSONObject {
        val s1 = effectiveScore(layer1)
        val s2 = effectiveScore(layer2)
        val s3 = effectiveScore(layer3)
        val s4 = effectiveScore(layer4)

        val weighted = (s1 * Cfg.W1 + s2 * Cfg.W2 + s3 * Cfg.W3 + s4 * Cfg.W4).toInt()
        // Escalate on a Layer 3 signature/blocklist hit OR a confident Layer 4 ML verdict.
        val hardHit = layer3.optJSONObject("rawData")?.optBoolean("hardHit") == true ||
            layer4.optJSONObject("rawData")?.optBoolean("hardHit") == true
        val finalScore = (if (hardHit) maxOf(weighted, Cfg.ESCALATION_MIN_SCORE) else weighted)
            .coerceIn(0, 100)

        val verdict = when {
            finalScore >= Cfg.THRESHOLD_MALICIOUS -> "MALICIOUS"
            finalScore >= Cfg.THRESHOLD_SUSPICIOUS -> "SUSPICIOUS"
            else -> "SAFE"
        }

        return JSONObject().apply {
            put("apkPath", apkPath)
            put("verdict", verdict)
            put("summary", buildSummary(verdict, finalScore, hardHit))
            put("overallRiskScore", finalScore)
            put("layer1", layer1)
            put("layer2", layer2)
            put("layer3", layer3)
            put("layer4", layer4)
            put("analysisTimestamp", System.currentTimeMillis())
            put("scoreBreakdown", JSONObject().apply {
                put("layer1", s1)
                put("layer2", s2)
                put("layer3", s3)
                put("layer4", s4)
                put("weighted", weighted)
                put("final", finalScore)
                put("escalated", hardHit)
            })
        }
    }

    /** Raw layer score, capped if the layer reported an analysis error. */
    private fun effectiveScore(layer: JSONObject): Int {
        val raw = layer.optInt("riskScore", 0)
        val errored = layer.optJSONObject("rawData")?.optBoolean("analysisError") == true
        return if (errored) minOf(raw, Cfg.ERRORED_LAYER_MAX_CONTRIBUTION) else raw
    }

    private fun erroredLayers(): List<String> = buildList {
        listOf(layer1, layer2, layer3, layer4).forEach { l ->
            if (l.optJSONObject("rawData")?.optBoolean("analysisError") == true) {
                add(l.optString("layerName", "a layer"))
            }
        }
    }

    private fun buildSummary(verdict: String, score: Int, hardHit: Boolean): String = buildString {
        val mlVerdict = layer4.optJSONObject("rawData")?.optString("mlVerdict")
        val mlVotes = layer4.optJSONObject("rawData")?.optInt("malVotes") ?: 0
        when (verdict) {
            "SAFE" -> append(
                "This APK appears safe (risk score $score/100). " +
                    "No significant threats detected across the four analysis layers.",
            )
            "SUSPICIOUS" -> append(
                "This APK has some suspicious characteristics (risk score $score/100). " +
                    "Review the layer findings carefully before installing.",
            )
            "MALICIOUS" -> {
                append("HIGH RISK: this APK is likely malicious (risk score $score/100). ")
                if (layer3.optJSONObject("rawData")?.optBoolean("hardHit") == true) {
                    append("A known malware signature or reputation hit was found. ")
                }
                if (mlVerdict == "malware") {
                    append("The ML ensemble classified it as malware ($mlVotes/5 models agree). ")
                }
                append("Installation is strongly discouraged.")
            }
        }
        val errored = erroredLayers()
        if (errored.isNotEmpty()) {
            append(" Note: ${errored.joinToString()} could not complete analysis, so this verdict is based on partial data.")
        }
    }
}
