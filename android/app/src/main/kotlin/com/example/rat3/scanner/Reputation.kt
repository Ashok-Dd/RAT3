package com.example.rat3.scanner

import android.content.Context
import org.json.JSONObject

/**
 * Loads the two reputation data files bundled in `assets/` for [Layer3SignatureScanner]:
 *  - `blocklist.json`  — SHA-256 hashes of known-malicious APK files
 *  - `trusted_certs.json` — package name → SHA-256 of its legitimate signing certificate(s)
 *
 * Both are optional; a missing or malformed file yields an empty result (logged, not fatal).
 */
object Reputation {

    fun loadBlocklist(context: Context): Set<String> = try {
        val json = context.assets.open("blocklist.json").bufferedReader().use { it.readText() }
        val arr = JSONObject(json).optJSONArray("hashes") ?: return emptySet()
        (0 until arr.length())
            .map { arr.getString(it).lowercase() }
            .filter { it.length == 64 && it.any { c -> c != '0' } }
            .toSet()
    } catch (t: Throwable) {
        ScanLog.w("Reputation.loadBlocklist", t)
        emptySet()
    }

    fun loadTrustedCerts(context: Context): Map<String, Set<String>> = try {
        val json = context.assets.open("trusted_certs.json").bufferedReader().use { it.readText() }
        val packages = JSONObject(json).optJSONObject("packages") ?: return emptyMap()
        buildMap {
            for (pkg in packages.keys()) {
                val arr = packages.getJSONArray(pkg)
                val hashes = (0 until arr.length())
                    .map { arr.getString(it).lowercase() }
                    .filter { it.length == 64 && it.any { c -> c != '0' } }
                    .toSet()
                if (hashes.isNotEmpty()) put(pkg, hashes)
            }
        }
    } catch (t: Throwable) {
        ScanLog.w("Reputation.loadTrustedCerts", t)
        emptyMap()
    }
}
