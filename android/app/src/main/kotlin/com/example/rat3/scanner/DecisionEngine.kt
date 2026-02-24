package com.example.rat3.scanner

import org.json.JSONObject

/**
 * DecisionEngine
 *
 * Fuses the four layer outputs into a single final verdict.
 *
 * Algorithm:
 *   weighted = L1×0.20 + L2×0.20 + L3×0.35 + L4×0.25
 *
 *   Override (escalation) rules — applied AFTER weighting:
 *     L3 ≥ 70  →  final score forced to ≥ 65   (signature hit = almost certainly malicious)
 *     L4 ≥ 80  →  final score forced to ≥ 65   (ML very confident)
 *
 *   Thresholds:
 *     final < 30  → SAFE
 *     30 ≤ final < 60 → SUSPICIOUS
 *     final ≥ 60  → MALICIOUS
 *
 * Returns a complete ScanResult JSON object (schema matches Dart ScanResult model).
 */
class DecisionEngine(
    private val apkPath: String,
    private val layer1:  JSONObject,
    private val layer2:  JSONObject,
    private val layer3:  JSONObject,
    private val layer4:  JSONObject,
) {

    companion object {
        private const val W1 = 0.20
        private const val W2 = 0.20
        private const val W3 = 0.35
        private const val W4 = 0.25

        private const val THRESHOLD_MALICIOUS  = 60
        private const val THRESHOLD_SUSPICIOUS = 30
        private const val OVERRIDE_MIN_SCORE   = 65
    }

    fun computeVerdict(): JSONObject {
        val s1 = layer1.optInt("riskScore", 0)
        val s2 = layer2.optInt("riskScore", 0)
        val s3 = layer3.optInt("riskScore", 0)
        val s4 = layer4.optInt("riskScore", 0)

        val weighted  = (s1 * W1 + s2 * W2 + s3 * W3 + s4 * W4).toInt()
        val escalate  = s3 >= 70 || s4 >= 80
        val finalScore= if (escalate) maxOf(weighted, OVERRIDE_MIN_SCORE) else weighted

        val verdict = when {
            finalScore >= THRESHOLD_MALICIOUS  -> "MALICIOUS"
            finalScore >= THRESHOLD_SUSPICIOUS -> "SUSPICIOUS"
            else                               -> "SAFE"
        }

        return JSONObject().apply {
            put("apkPath",          apkPath)
            put("verdict",          verdict)
            put("summary",          buildSummary(verdict, finalScore, s1, s2, s3, s4))
            put("overallRiskScore", finalScore.coerceIn(0, 100))
            put("layer1",           layer1)
            put("layer2",           layer2)
            put("layer3",           layer3)
            put("layer4",           layer4)
            put("analysisTimestamp",System.currentTimeMillis())
            put("scoreBreakdown", JSONObject().apply {
                put("layer1",   s1)
                put("layer2",   s2)
                put("layer3",   s3)
                put("layer4",   s4)
                put("weighted", weighted)
                put("final",    finalScore)
                put("escalated",escalate)
            })
        }
    }

    // ─── Human-readable summary ────────────────────────────────────────

    private fun buildSummary(
        verdict: String,
        score: Int,
        s1: Int, s2: Int, s3: Int, s4: Int,
    ): String = buildString {
        when (verdict) {
            "SAFE" -> {
                append("This APK appears safe (risk score: $score/100). ")
                append("No significant threats detected across all 4 analysis layers.")
            }
            "SUSPICIOUS" -> {
                append("This APK has suspicious characteristics (risk score: $score/100). ")
                if (s1 >= THRESHOLD_SUSPICIOUS) append("Manifest issues detected. ")
                if (s2 >= THRESHOLD_SUSPICIOUS) append("Permission mismatches found. ")
                if (s3 >= THRESHOLD_SUSPICIOUS) append("Partial signature matches. ")
                if (s4 >= THRESHOLD_SUSPICIOUS) append("ML model flagged anomalies. ")
                append("Review the findings carefully before installing.")
            }
            "MALICIOUS" -> {
                append("⚠ HIGH RISK: This APK is likely malicious (risk score: $score/100). ")
                if (s3 >= THRESHOLD_MALICIOUS) append("Known malware signatures matched. ")
                if (s4 >= THRESHOLD_MALICIOUS) append("ML model detected malware patterns. ")
                if (s1 >= THRESHOLD_MALICIOUS) append("Critical manifest anomalies found. ")
                append("Installation is strongly discouraged.")
            }
            else -> append("Analysis complete. Risk score: $score/100.")
        }
    }
}