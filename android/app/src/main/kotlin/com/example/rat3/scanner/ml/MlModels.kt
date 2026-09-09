package com.example.rat3.scanner.ml

import android.content.Context
import com.example.rat3.scanner.ScanLog
import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.exp
import kotlin.math.ln

/**
 * On-device evaluators for the malware-detection models exported by
 * `ml/export_models_for_android.py` into `assets/ml/`.
 *
 * Four tree-ensemble models (Random Forest, Decision Tree, AdaBoost, XGBoost)
 * classify an APK's 241-feature vector (TUANDROMD schema) as goodware / malware.
 * They share one `VarianceThreshold` mask (241 → 199) applied before any model
 * runs. [MlEnsemble] reproduces the Flask app's `ensemble_verdict`. The Stacking
 * model stays server-only (its KNN base learner needs a SMOTE-resampled training
 * set that can't be bundled compactly).
 */

private fun sigmoid(z: Double): Double = 1.0 / (1.0 + exp(-z))

// ── Generic tree ─────────────────────────────────────────────────────────────

private class Tree(
    private val feat: IntArray,
    private val thr: DoubleArray,
    private val left: IntArray,
    private val right: IntArray,
    private val leaf: DoubleArray, // "prob" for sklearn trees, "leaf" for xgboost
    /** sklearn splits go left on `x <= threshold`; xgboost goes "yes" on `x < split_condition`. */
    private val strict: Boolean = false,
) {
    /** Value at the reached leaf. sklearn: P(malware); xgboost: raw margin contribution. */
    fun eval(x: DoubleArray): Double {
        var node = 0
        while (feat[node] != -2) {
            val goLeft = if (strict) x[feat[node]] < thr[node] else x[feat[node]] <= thr[node]
            node = if (goLeft) left[node] else right[node]
        }
        return leaf[node]
    }

    /** sklearn tree class prediction (argmax of [1-p, p]). */
    fun predictsMalware(x: DoubleArray): Boolean = eval(x) >= 0.5

    companion object {
        fun fromJson(o: JSONObject, strict: Boolean = false): Tree {
            val leafKey = if (o.has("prob")) "prob" else "leaf"
            return Tree(
                feat = o.getJSONArray("feat").toIntArray(),
                thr = o.getJSONArray("thr").toDoubleArray(),
                left = o.getJSONArray("left").toIntArray(),
                right = o.getJSONArray("right").toIntArray(),
                leaf = o.getJSONArray(leafKey).toDoubleArray(),
                strict = strict,
            )
        }
    }
}

private fun JSONArray.toIntArray() = IntArray(length()) { getInt(it) }
private fun JSONArray.toDoubleArray() = DoubleArray(length()) { getDouble(it) }

// ── Model kinds ──────────────────────────────────────────────────────────────

/** All models return P(malware) for a 199-length variance-filtered vector. */
private sealed interface Model {
    fun malwareProb(x: DoubleArray): Double
}

private class TreeEnsemble(private val trees: List<Tree>, private val combine: String, private val weights: DoubleArray?) : Model {
    override fun malwareProb(x: DoubleArray): Double = when (combine) {
        "samme" -> {
            val w = weights ?: DoubleArray(trees.size) { 1.0 }
            var num = 0.0
            var den = 0.0
            for (i in trees.indices) {
                val s = if (trees[i].predictsMalware(x)) 1.0 else -1.0
                num += s * w[i]
                den += w[i]
            }
            sigmoid(2.0 * num / den)
        }
        else -> trees.sumOf { it.eval(x) } / trees.size // "avg"
    }

    companion object {
        fun fromJson(o: JSONObject): TreeEnsemble {
            val arr = o.getJSONArray("trees")
            val trees = (0 until arr.length()).map { Tree.fromJson(arr.getJSONObject(it)) }
            val w = o.optJSONArray("weights")?.toDoubleArray()
            return TreeEnsemble(trees, o.getString("combine"), w)
        }
    }
}

private class XgbModel(private val trees: List<Tree>, private val baseScore: Double) : Model {
    private val baseMargin = ln(baseScore / (1.0 - baseScore))
    override fun malwareProb(x: DoubleArray): Double =
        sigmoid(baseMargin + trees.sumOf { it.eval(x) })

    companion object {
        fun fromJson(o: JSONObject): XgbModel {
            val arr = o.getJSONArray("trees")
            val trees = (0 until arr.length()).map { Tree.fromJson(arr.getJSONObject(it), strict = true) }
            return XgbModel(trees, o.getDouble("base_score"))
        }
    }
}

// ── Ensemble ─────────────────────────────────────────────────────────────────

data class ModelVote(val name: String, val malwareProbPct: Double, val prediction: String)

data class MlResult(
    val available: Boolean,
    val verdict: String,          // "malware" | "goodware" | "unknown"
    val scorePct: Int,            // avg malware probability, 0..100
    val riskLevel: String,        // Safe / Low / Medium / High / Critical
    val malVotes: Int,
    val goodVotes: Int,
    val perModel: List<ModelVote>,
)

/**
 * Loads the four exported tree models once and reproduces `ensemble_verdict`:
 * majority vote on labels, risk score = mean malware probability.
 */
class MlEnsemble private constructor(
    private val mask: BooleanArray,
    private val models: Map<String, Model>,
) {

    /** @param vec241 binary feature vector in canonical `feature_list.json` order. */
    fun classify(vec241: DoubleArray): MlResult {
        if (models.isEmpty()) {
            return MlResult(false, "unknown", 0, "Unknown", 0, 0, emptyList())
        }
        val filtered = DoubleArray(mask.count { it })
        var j = 0
        for (i in vec241.indices) if (mask[i]) filtered[j++] = vec241[i]

        val votes = models.map { (name, model) ->
            val p = model.malwareProb(filtered).coerceIn(0.0, 1.0) * 100.0
            ModelVote(name, p, if (p >= 50.0) "malware" else "goodware")
        }
        val mal = votes.count { it.prediction == "malware" }
        val good = votes.size - mal
        val score = votes.sumOf { it.malwareProbPct } / votes.size
        val verdict = if (mal >= good) "malware" else "goodware"
        val level = when {
            score >= 80 -> "Critical"
            score >= 60 -> "High"
            score >= 40 -> "Medium"
            score >= 20 -> "Low"
            else -> "Safe"
        }
        return MlResult(true, verdict, score.toInt(), level, mal, good, votes)
    }

    companion object {
        private const val DIR = "ml"
        private val NAMES = listOf("random_forest", "decision_tree", "adaboost", "xgboost")

        @Volatile
        private var cached: MlEnsemble? = null

        fun load(context: Context): MlEnsemble = cached ?: synchronized(this) {
            cached ?: buildFrom { name ->
                try {
                    context.assets.open("$DIR/$name").bufferedReader().use { it.readText() }
                } catch (t: Throwable) {
                    null
                }
            }.also { cached = it }
        }

        /** Shared builder — [readAsset] returns the JSON text for `variance_mask.json` / `<model>.json`. */
        fun buildFrom(readAsset: (String) -> String?): MlEnsemble {
            val mask = try {
                val arr = JSONArray(readAsset("variance_mask.json"))
                BooleanArray(arr.length()) { arr.getBoolean(it) }
            } catch (t: Throwable) {
                ScanLog.w("MlEnsemble.mask", t)
                BooleanArray(241) { true }
            }

            val models = LinkedHashMap<String, Model>()
            for (name in NAMES) {
                val text = readAsset("$name.json") ?: continue
                try {
                    val o = JSONObject(text)
                    models[name] = when (o.getString("kind")) {
                        "tree_ensemble" -> TreeEnsemble.fromJson(o)
                        "xgboost" -> XgbModel.fromJson(o)
                        
                        else -> continue
                    }
                } catch (t: Throwable) {
                    ScanLog.w("MlEnsemble.load[$name]", t)
                }
            }
            return MlEnsemble(mask, models)
        }
    }
}
