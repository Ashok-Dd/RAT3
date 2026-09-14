package com.example.rat3.scanner.ml

import android.content.Context
import com.example.rat3.scanner.ApkContext
import com.example.rat3.scanner.ScanLog
import org.json.JSONArray

/**
 * Builds the 241-element binary TUANDROMD feature vector from an [ApkContext].
 *
 * Mirrors `ml/apk_extractor.py`:
 *  - permission features: bare permission name present in the manifest
 *  - `activityCalled`: any `<activity>` declared
 *  - API features (names starting with `L`): the class + member appear adjacent
 *    in the DEX string dump (tolerating `->` / `.` separators)
 *
 * Feature order comes from `assets/ml/feature_list.json` (identical to the file
 * the models were trained against).
 */
object TuandromdFeatures {

    data class Extraction(val vector: DoubleArray, val permissionsFound: List<String>, val apisFound: List<String>)

    private const val ASSET = "ml/feature_list.json"

    @Volatile
    private var names: List<String>? = null

    private fun featureNames(context: Context): List<String> = names ?: synchronized(this) {
        names ?: run {
            val text = context.assets.open(ASSET).bufferedReader().use { it.readText() }
            val arr = JSONArray(text)
            List(arr.length()) { arr.getString(it) }.also { names = it }
        }
    }

    fun extract(context: Context, ctx: ApkContext): Extraction {
        val order = featureNames(context)
        val vec = DoubleArray(order.size)
        val permsFound = mutableListOf<String>()
        val apisFound = mutableListOf<String>()

        val manifest = ctx.manifestText
        val declared = bareNamesFromManifest(manifest) + ctx.permissions.map { it.substringAfterLast('.').uppercase() }

        for ((i, name) in order.withIndex()) {
            when {
                name == "activityCalled" -> if (ctx.hasAnyActivity) vec[i] = 1.0

                name.startsWith("L") && name.contains("->") -> {
                    if (dexHasApi(ctx.dexText, name)) {
                        vec[i] = 1.0
                        apisFound += name
                    }
                }

                else -> {
                    val perm = name.uppercase()
                    if (perm in declared || Regex("\\b${Regex.escape(perm)}\\b").containsMatchIn(manifest)) {
                        vec[i] = 1.0
                        permsFound += name
                    }
                }
            }
        }
        return Extraction(vec, permsFound, apisFound)
    }

    /** `android.permission.X`, `android.Manifest.permission.X`, `com.<pkg>.permission.X`. */
    private fun bareNamesFromManifest(manifest: String): Set<String> {
        val re = Regex(
            "(?:android\\.permission\\.|android\\.Manifest\\.permission\\.|com\\.\\w+\\.permission\\.)([A-Z_0-9]+)",
            RegexOption.IGNORE_CASE,
        )
        return re.findAll(manifest).map { it.groupValues[1].uppercase() }.toSet()
    }

    private fun dexHasApi(dex: String, api: String): Boolean {
        val parts = api.split("->", limit = 2)
        if (parts.size != 2) return dex.contains(api)
        return try {
            Regex(Regex.escape(parts[0]) + "[.>\\-]+" + Regex.escape(parts[1])).containsMatchIn(dex)
        } catch (t: Throwable) {
            ScanLog.w("TuandromdFeatures.dexHasApi", t)
            dex.contains(parts[0]) && dex.contains(parts[1])
        }
    }
}
