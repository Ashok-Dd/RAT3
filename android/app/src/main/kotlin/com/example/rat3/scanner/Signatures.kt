package com.example.rat3.scanner

import android.content.Context
import org.json.JSONArray

/**
 * Malware signature definitions for [Layer3SignatureScanner].
 *
 * Signatures are loaded from `assets/signatures.json`; [DEFAULTS] is a byte-for-byte fallback
 * used only if that asset is missing or malformed. Network-indicator patterns (`.onion`,
 * dynamic-DNS) are intentionally NOT signatures here — Layer 3 scores those once in
 * `detectNetworkIndicators`, so keeping them out avoids the old double-counting bug.
 */
data class Signature(
    val id: String,
    val name: String,
    val family: String,
    val pattern: String,
    val isRegex: Boolean,
    val riskWeight: Int,
) {
    private val compiled: Regex? = if (isRegex) runCatching { Regex(pattern) }.getOrNull() else null

    /** True if this signature matches anywhere in [content]. */
    fun matches(content: String): Boolean =
        if (isRegex) compiled?.containsMatchIn(content) == true else content.contains(pattern)
}

object Signatures {

    fun load(context: Context): List<Signature> = try {
        val json = context.assets.open("signatures.json").bufferedReader().use { it.readText() }
        parse(json).ifEmpty { DEFAULTS }
    } catch (t: Throwable) {
        ScanLog.w("Signatures.load", t)
        DEFAULTS
    }

    fun parse(json: String): List<Signature> {
        val arr = JSONArray(json)
        return (0 until arr.length()).mapNotNull { i ->
            runCatching {
                val o = arr.getJSONObject(i)
                Signature(
                    id = o.getString("id"),
                    name = o.getString("name"),
                    family = o.getString("family"),
                    pattern = o.getString("pattern"),
                    isRegex = o.optBoolean("isRegex", false),
                    riskWeight = o.optInt("riskWeight", 20),
                )
            }.onFailure { ScanLog.w("Signatures.parse[$i]", it) }.getOrNull()
        }
    }

    /** Must stay identical to `assets/signatures.json`. */
    val DEFAULTS: List<Signature> = listOf(
        Signature("RAT3-001", "AndroRAT marker", "AndroRAT", "AndroRAT", false, 50),
        Signature("RAT3-002", "SpyNote package", "SpyNote", "com.spynote", false, 55),
        Signature("RAT3-003", "Crypto miner stratum pool", "CryptoMiner", "stratum+tcp://", false, 40),
        Signature("RAT3-004", "Embedded su binary path", "RootExploit", "/system/xbin/su", false, 45),
        Signature("RAT3-005", "SIM-country overlay check", "BankBot", "getSimCountryIso", false, 20),
        Signature("RAT3-006", "SMS-stealer log reader", "SMSStealer", "content://sms", false, 25),
        Signature("RAT3-007", "Ransomware locked extension", "Ransomware", """\.locked["'<]""", true, 55),
        Signature("RAT3-008", "Fake Google Play SDK", "Adware", "com.google.play.fakesdk", false, 45),
        Signature("RAT3-009", "AndroRAT config marker", "AndroRAT", "androrat.properties", false, 55),
        Signature("RAT3-010", "MobiHok / SpyMax marker", "SpyMax", "spymax", false, 50),
    )
}
