package com.example.rat3.scanner

import android.content.Context
import com.example.rat3.scanner.ml.MlEnsemble
import com.example.rat3.scanner.ml.TuandromdFeatures
import org.json.JSONArray
import org.json.JSONObject

/**
 * Layer 4 — ML Malware Classifier.
 *
 * Extracts the 241-feature TUANDROMD vector from the APK and runs the on-device
 * 4-model ensemble (Random Forest, Decision Tree, AdaBoost, XGBoost — see
 * [MlEnsemble]) exported to `assets/ml/`. The verdict is a majority vote; the
 * layer risk score is the mean malware probability across the models — exactly
 * like the training-time Flask `ensemble_verdict`. A 5th model (Stacking) exists
 * but is server-only; see `ml/feature_schema.md` for why.
 */
class Layer4MlClassifier(
    private val ctx: ApkContext,
    private val context: Context,
) {

    fun analyze(): JSONObject {
        return try {
            val extraction = TuandromdFeatures.extract(context, ctx)
            val ml = MlEnsemble.load(context).classify(extraction.vector)

            if (!ml.available) {
                return buildLayerJson(
                    layerName = "ML Malware Classifier",
                    riskScore = 0,
                    findings = listOf(finding("ML models are not bundled in this build.", isWarning = false)),
                    analysisError = true,
                )
            }

            val findings = mutableListOf(
                finding(
                    "Ensemble verdict: ${ml.verdict.uppercase()} — ${ml.malVotes}/${ml.malVotes + ml.goodVotes} models " +
                        "flagged malware (mean probability ${ml.scorePct}%, ${ml.riskLevel} risk).",
                    isWarning = ml.verdict == "malware",
                    category = "ml_verdict",
                ),
            )
            ml.perModel.forEach {
                findings += finding(
                    "${prettyName(it.name)}: ${it.prediction} (${"%.1f".format(it.malwareProbPct)}% malware)",
                    isWarning = it.prediction == "malware",
                    category = "ml_model",
                )
            }
            if (extraction.apisFound.isNotEmpty()) {
                findings += finding(
                    "Dangerous APIs seen: ${extraction.apisFound.take(6).joinToString { it.substringAfterLast('/') }}",
                    isWarning = true,
                    category = "ml_feature",
                )
            }
            if (ctx.manifestParseFailed) {
                // The platform manifest parser failed, so ApkContext fell back to a raw byte
                // scan for permissions (ApkContext.rawScanPermissions) — that scan only covers
                // the known dangerous/suspicious permission set, not all 212 permission features
                // the model was trained on. The prediction below is real, but ran on a degraded
                // feature vector, so say so instead of presenting it with full confidence.
                findings += finding(
                    "Manifest could not be fully parsed, so some permission features may be " +
                        "missing from the model input — treat this verdict as lower-confidence.",
                    isWarning = true,
                    category = "ml_feature",
                )
            }

            buildLayerJson(
                layerName = "ML Malware Classifier",
                riskScore = ml.scorePct,
                findings = findings,
                rawData = JSONObject().apply {
                    put("mlVerdict", ml.verdict)
                    put("malVotes", ml.malVotes)
                    put("goodVotes", ml.goodVotes)
                    put("riskLevel", ml.riskLevel)
                    put("permissionsMatched", extraction.permissionsFound.size)
                    put("apisMatched", extraction.apisFound.size)
                    put("featuresDegraded", ctx.manifestParseFailed)
                    put("perModel", JSONArray().apply {
                        ml.perModel.forEach {
                            put(JSONObject().apply {
                                put("name", it.name)
                                put("prediction", it.prediction)
                                put("malwareProbPct", it.malwareProbPct)
                            })
                        }
                    })
                    // Layer 3 uses `hardHit` to decide escalation; mirror that here. A majority
                    // (not unanimous) malware vote is enough — requiring all 4 models to agree
                    // let a confident 3/4 majority (e.g. 69% mean probability) get averaged down
                    // to a SAFE verdict by the other three layers instead of escalating.
                    put("hardHit", ml.verdict == "malware" && ml.malVotes >= 3)
                },
            )
        } catch (e: Exception) {
            ScanLog.w("Layer4MlClassifier", e)
            buildLayerJson(
                layerName = "ML Malware Classifier",
                riskScore = 0,
                findings = listOf(finding("ML classification failed: ${e.message}", isWarning = false)),
                analysisError = true,
            )
        }
    }

    private fun prettyName(id: String): String = when (id) {
        "random_forest" -> "Random Forest"
        "decision_tree" -> "Decision Tree"
        "adaboost" -> "AdaBoost"
        "xgboost" -> "XGBoost"
        else -> id // defensive: MlEnsemble only ever loads the 4 names above
    }
}
