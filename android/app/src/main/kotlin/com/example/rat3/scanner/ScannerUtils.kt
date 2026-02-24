package com.example.rat3.scanner

import org.json.JSONArray
import org.json.JSONObject

/**
 * Shared utility functions used by all four scanner layers.
 * Kept in one file to avoid duplication.
 */

/**
 * Creates a single Finding JSON object.
 *
 * @param message   Human-readable finding description shown in the UI.
 * @param isWarning If true, displayed with a warning icon; false = info icon.
 * @param category  Optional machine-readable category tag (e.g. "obfuscation", "network").
 */
fun finding(
    message: String,
    isWarning: Boolean,
    category: String? = null,
): JSONObject = JSONObject().apply {
    put("message", message)
    put("isWarning", isWarning)
    category?.let { put("category", it) }
}

/**
 * Builds the standard layer result JSON object returned to Flutter.
 *
 * Schema (matches LayerResult Dart model):
 * {
 *   "layerName": "...",
 *   "riskScore": 0–100,
 *   "findings": [ { "message": "...", "isWarning": bool, "category": "..." } ],
 *   "rawData": { ... layer-specific details ... }
 * }
 */
fun buildLayerJson(
    layerName: String,
    riskScore: Int,
    findings: List<JSONObject>,
    rawData: JSONObject,
): JSONObject = JSONObject().apply {
    put("layerName", layerName)
    put("riskScore", riskScore.coerceIn(0, 100))
    put("findings", JSONArray(findings))
    put("rawData", rawData)
}