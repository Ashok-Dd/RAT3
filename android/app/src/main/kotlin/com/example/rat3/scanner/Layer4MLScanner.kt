package com.example.rat3.scanner

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.util.zip.ZipFile

/**
 * Layer 4 — Machine Learning Prediction
 *
 * Extracts a 17-feature vector from the APK and passes it to a classifier.
 *
 * HOW TO REPLACE THE DUMMY MODEL WITH YOUR REAL .pkl
 * ═══════════════════════════════════════════════════
 * See the full guide in the top-comment of the previous version.
 * Short version:
 *   1. Use Chaquopy or TFLite to run your model on Android.
 *   2. Replace the DummyModel.predict(features) call below.
 *   3. Keep the feature vector order matching ml/feature_schema.md.
 */
class Layer4MLScanner(
    private val apkFile: File,
    private val context: Context,
) {

    fun analyze(): JSONObject {
        val findings = mutableListOf<JSONObject>()

        return try {
            val features = buildFeatureVector()

            // ── REPLACE THIS LINE WITH YOUR REAL MODEL CALL ──────────────
            val prediction = DummyModel.predict(features)
            // ─────────────────────────────────────────────────────────────

            val label = when (prediction.label) {
                0    -> "SAFE"
                1    -> "SUSPICIOUS"
                else -> "MALICIOUS"
            }
            val pct = (prediction.confidence * 100).toInt()

            findings += finding(
                "ML Prediction: $label (confidence: $pct%)",
                isWarning = prediction.label > 0,
                category = "ml_result"
            )
            findings += finding(
                "Using DummyModel. Replace with real_model.pkl for production.",
                isWarning = false,
                category = "ml_info"
            )

            buildLayerJson(
                layerName = "ML Prediction",
                riskScore = prediction.riskScore,
                findings = findings,
                rawData = JSONObject().apply {
                    put("predictionLabel", label)
                    put("confidencePct", pct)
                    put("featureCount", features.size)
                    put("modelType", "DummyHeuristicModel_v1")
                }
            )
        } catch (e: Exception) {
            buildLayerJson(
                layerName = "ML Prediction",
                riskScore = 10,
                findings = listOf(finding("ML layer skipped: ${e.message}", isWarning = false)),
                rawData = JSONObject()
            )
        }
    }

    private fun buildFeatureVector(): FloatArray {
        var numPermissions           = 0
        var numDangerousPermissions  = 0
        var numSuspiciousPermissions = 0
        var hasSms                   = 0
        var hasCamera                = 0
        var hasLocation              = 0
        var hasAudio                 = 0
        var numNativeLibs            = 0
        var dexSizeKB                = 0L
        var numBase64Blobs           = 0
        var hasRawIps                = 0

        ZipFile(apkFile).use { zip ->
            // Manifest scan
            zip.getEntry("AndroidManifest.xml")?.let { entry ->
                val raw = zip.getInputStream(entry).readBytes().toString(Charsets.ISO_8859_1)

                for (perm in Layer1SafetyAnalyzer.DANGEROUS_PERMISSIONS) {
                    if (raw.contains(perm.takeLast(22))) {
                        numPermissions++
                        numDangerousPermissions++
                        when {
                            perm.contains("SMS")           -> hasSms      = 1
                            perm.contains("CAMERA")        -> hasCamera   = 1
                            perm.contains("LOCATION")      -> hasLocation = 1
                            perm.contains("RECORD_AUDIO")  -> hasAudio    = 1
                        }
                    }
                }
                for (perm in Layer1SafetyAnalyzer.SUSPICIOUS_PERMISSIONS) {
                    if (raw.contains(perm.takeLast(20))) {
                        numPermissions++
                        numSuspiciousPermissions++
                    }
                }
            }

            // DEX + native lib scan — fix: use asSequence() on Enumeration
            zip.entries().asSequence().forEach { entry ->
                when {
                    entry.name.matches(Regex("""classes\d*\.dex""")) -> {
                        dexSizeKB += entry.size / 1024
                        // Read first 64KB for quick heuristic scan
                        val bytes = zip.getInputStream(entry).use { stream ->
                            val buf = ByteArray(65536)
                            val read = stream.read(buf)
                            if (read > 0) buf.copyOf(read) else ByteArray(0)
                        }
                        val sample = bytes.toString(Charsets.ISO_8859_1)
                        numBase64Blobs += Regex("[A-Za-z0-9+/]{200,}={0,2}")
                            .findAll(sample).count()
                        if (Regex("""(\d{1,3}\.){3}\d{1,3}:\d{4,5}""").containsMatchIn(sample)) {
                            hasRawIps = 1
                        }
                    }
                    entry.name.endsWith(".so") -> numNativeLibs++
                }
            }
        }

        return floatArrayOf(
            numPermissions.toFloat(),            // [0]
            numDangerousPermissions.toFloat(),   // [1]
            numSuspiciousPermissions.toFloat(),  // [2]
            0f,                                  // [3] exportedComponents (from Layer 1)
            0f,                                  // [4] targetSdk (from Layer 1)
            hasSms.toFloat(),                    // [5]
            hasCamera.toFloat(),                 // [6]
            hasLocation.toFloat(),               // [7]
            hasAudio.toFloat(),                  // [8]
            numNativeLibs.toFloat(),             // [9]
            0f,                                  // [10] hasObfuscation (from Layer 3)
            dexSizeKB.toFloat(),                 // [11]
            numBase64Blobs.toFloat(),            // [12]
            hasRawIps.toFloat(),                 // [13]
            0f,                                  // [14] layer1RiskScore
            0f,                                  // [15] layer2RiskScore
            0f,                                  // [16] layer3RiskScore
        )
    }
}

// ── Dummy Model ───────────────────────────────────────────────────────────────

object DummyModel {

    data class Prediction(
        val label: Int,
        val confidence: Float,
        val riskScore: Int,
    )

    fun predict(features: FloatArray): Prediction {
        val numDangerous  = features.getOrElse(1) { 0f }
        val numSuspicious = features.getOrElse(2) { 0f }
        val hasSms        = features.getOrElse(5) { 0f }
        val hasLocation   = features.getOrElse(7) { 0f }
        val hasAudio      = features.getOrElse(8) { 0f }
        val numNativeLibs = features.getOrElse(9) { 0f }
        val dexSizeKB     = features.getOrElse(11) { 0f }
        val numBase64     = features.getOrElse(12) { 0f }
        val hasRawIps     = features.getOrElse(13) { 0f }

        val score = (
            numDangerous  * 5f  +
            numSuspicious * 9f  +
            hasSms        * 18f +
            hasLocation   * 8f  +
            hasAudio      * 8f  +
            numNativeLibs * 4f  +
            numBase64     * 3f  +
            hasRawIps     * 20f +
            if (dexSizeKB > 5000f) 15f else 0f
        ).coerceIn(0f, 100f)

        val label = when {
            score >= 60f -> 2
            score >= 28f -> 1
            else         -> 0
        }

        val confidence = when (label) {
            2    -> (0.70f + (score - 60f) / 200f).coerceIn(0.55f, 0.99f)
            1    -> (0.62f + (score - 28f) / 200f).coerceIn(0.55f, 0.90f)
            else -> (0.88f - score / 250f).coerceIn(0.60f, 0.98f)
        }

        return Prediction(label, confidence, score.toInt())
    }
}