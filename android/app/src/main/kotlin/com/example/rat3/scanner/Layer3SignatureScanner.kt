package com.example.rat3.scanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.zip.ZipFile

/**
 * Layer 3 — Malware Signature Scanner
 *
 * Scans APK content against a signature database (assets/signatures.json) plus
 * heuristic checks for obfuscation, suspicious native libs, and network indicators.
 */
class Layer3SignatureScanner(
    private val apkFile: File,
    private val context: Context,
) {

    private data class Signature(
        val id: String,
        val name: String,
        val family: String,
        val pattern: String,
        val isRegex: Boolean,
        val riskWeight: Int,
    )

    fun analyze(): JSONObject {
        val findings      = mutableListOf<JSONObject>()
        var riskScore     = 0
        var matchedFamily = "None"

        return try {
            val signatures = loadSignatures()
            val apkContent = extractScanContent()

            // 1. Signature matching
            for (sig in signatures) {
                val hit = if (sig.isRegex) {
                    try { Regex(sig.pattern).containsMatchIn(apkContent) } catch (e: Exception) { false }
                } else {
                    apkContent.contains(sig.pattern)
                }
                if (hit) {
                    riskScore    += sig.riskWeight
                    matchedFamily = sig.family
                    findings += finding(
                        "Signature match [${sig.id}]: ${sig.name} — family: ${sig.family}",
                        isWarning = true,
                        category = "signature"
                    )
                }
            }

            // 2. Obfuscation
            riskScore += detectObfuscation(apkContent, findings)

            // 3. Native libraries
            riskScore += detectNativeLibraries(findings)

            // 4. Network indicators
            riskScore += detectNetworkIndicators(apkContent, findings)

            if (findings.none { it.optBoolean("isWarning") }) {
                findings += finding("No known malware signatures detected. ✓", isWarning = false)
            }

            buildLayerJson(
                layerName = "Malware Signature Check",
                riskScore = riskScore,
                findings = findings,
                rawData = JSONObject().apply {
                    put("signaturesChecked", signatures.size)
                    put("matchedFamily", matchedFamily)
                }
            )
        } catch (e: Exception) {
            buildLayerJson(
                layerName = "Malware Signature Check",
                riskScore = 20,
                findings = listOf(finding("Signature scan error: ${e.message}", isWarning = true)),
                rawData = JSONObject()
            )
        }
    }

    private fun loadSignatures(): List<Signature> {
        return try {
            val json = context.assets.open("signatures.json").bufferedReader().use { it.readText() }
            val arr  = JSONArray(json)
            (0 until arr.length()).map { i ->
                val obj = arr.getJSONObject(i)
                Signature(
                    id         = obj.getString("id"),
                    name       = obj.getString("name"),
                    family     = obj.getString("family"),
                    pattern    = obj.getString("pattern"),
                    isRegex    = obj.optBoolean("isRegex", false),
                    riskWeight = obj.optInt("riskWeight", 20)
                )
            }
        } catch (e: Exception) {
            builtInSignatures()
        }
    }

    private fun builtInSignatures(): List<Signature> = listOf(
        Signature("B001", "AndroRAT marker",           "AndroRAT",    "AndroRAT",          false, 50),
        Signature("B002", "SpyNote package",           "SpyNote",     "com.spynote",       false, 55),
        Signature("B003", "Crypto miner stratum",      "CryptoMiner", "stratum+tcp",       false, 40),
        Signature("B004", "Root shell access",         "RootExploit", "/system/xbin/su",   false, 55),
        Signature("B005", "Banking trojan SIM check",  "BankBot",     "getSimCountryIso",  false, 25),
        Signature("B006", "SMS stealer log reader",    "SMSStealer",  "readSmsLog",        false, 35),
        Signature("B007", "Ransomware locked ext",     "Ransomware",  "\\.locked",         true,  60),
        Signature("B008", "Tor .onion address",        "Covert",      ".onion",            false, 40),
        Signature("B009", "Dynamic DNS domain",        "RAT",         "dyndns.org",        false, 20),
        Signature("B010", "Fake Google Play SDK",      "Adware",      "com.google.play.fakesdk", false, 45)
    )

    private fun detectObfuscation(content: String, findings: MutableList<JSONObject>): Int {
        var score = 0

        val b64Matches = Regex("[A-Za-z0-9+/]{200,}={0,2}").findAll(content).count()
        if (b64Matches > 5) {
            score += 15
            findings += finding(
                "$b64Matches large Base64 blob(s) found — possible encrypted payload.",
                isWarning = true,
                category = "obfuscation"
            )
        }

        val shortClassCount = Regex("""L[a-z]/[a-z];""").findAll(content).count()
        if (shortClassCount > 20) {
            score += 10
            findings += finding(
                "Heavy class-name obfuscation ($shortClassCount single-letter classes).",
                isWarning = true,
                category = "obfuscation"
            )
        }

        return score.coerceAtMost(30)
    }

    private fun detectNativeLibraries(findings: MutableList<JSONObject>): Int {
        var score = 0
        val flaggedNames = setOf("libhook", "libinject", "libspy", "libroot", "libsuperhide")

        ZipFile(apkFile).use { zip ->
            val libs = zip.entries().asSequence()
                .filter { it.name.endsWith(".so") }
                .map { it.name }
                .toList()

            val flagged = libs.filter { lib -> flaggedNames.any { lib.contains(it) } }

            if (flagged.isNotEmpty()) {
                score += 30
                findings += finding(
                    "Suspicious native libraries: ${flagged.joinToString()}",
                    isWarning = true,
                    category = "native_lib"
                )
            } else if (libs.isNotEmpty()) {
                val warn = libs.size > 3
                if (warn) score += 10
                findings += finding(
                    "${libs.size} native .so library(s) found.",
                    isWarning = warn,
                    category = "native_lib"
                )
            }
        }

        return score.coerceAtMost(40)
    }

    private fun detectNetworkIndicators(content: String, findings: MutableList<JSONObject>): Int {
        var score = 0

        val ips = Regex("""(\d{1,3}\.){3}\d{1,3}:\d{4,5}""")
            .findAll(content).take(5).map { it.value }.toList()
        if (ips.isNotEmpty()) {
            score += 20
            findings += finding(
                "Hardcoded IP:port addresses: ${ips.joinToString()} — possible C2 server.",
                isWarning = true,
                category = "network"
            )
        }

        if (content.contains(".onion")) {
            score += 35
            findings += finding(
                ".onion (Tor) address found — rare in legitimate apps.",
                isWarning = true,
                category = "network"
            )
        }

        listOf("dyndns.org", "no-ip.com", "duckdns.org", "afraid.org").forEach { domain ->
            if (content.contains(domain)) {
                score += 15
                findings += finding(
                    "Dynamic DNS domain: $domain — commonly abused by malware.",
                    isWarning = true,
                    category = "network"
                )
            }
        }

        return score.coerceAtMost(50)
    }

    private fun extractScanContent(): String {
        val sb = StringBuilder()
        val scanExtensions = setOf("dex", "xml", "json", "js", "html", "txt")

        ZipFile(apkFile).use { zip ->
            zip.entries().asSequence()
                .filter { !it.isDirectory }
                .filter { entry -> entry.name.substringAfterLast('.').lowercase() in scanExtensions }
                .take(25)
                .forEach { entry ->
                    try {
                        zip.getInputStream(entry).use { stream ->
                            sb.append(stream.readBytes().toString(Charsets.ISO_8859_1))
                        }
                    } catch (e: Exception) {
                        // Skip unreadable entries
                    }
                }
        }
        return sb.toString()
    }
}