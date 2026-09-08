package com.example.rat3.scanner

import android.content.Context
import org.json.JSONObject
import com.example.rat3.scanner.ScannerConfig.Layer3 as Cfg

/**
 * Layer 3 — Malware Signature & Reputation Check.
 *
 *  1. SHA-256 file blocklist (`assets/blocklist.json`) — an exact hit forces a malicious verdict.
 *  2. Signature patterns (`assets/signatures.json` via [Signatures]).
 *  3. Signing-certificate check (`assets/trusted_certs.json`) — a trusted package name signed by
 *     the wrong certificate is a repackaging / trojanisation indicator.
 *  4. Obfuscation, suspicious native libraries, and network (C2) indicators.
 *
 * `rawData.hardHit` is set true when 1, 2 or 3 produced a real detection; the decision engine
 * uses that (not a raw score threshold) to decide whether to escalate the verdict.
 */
class Layer3SignatureScanner(
    private val ctx: ApkContext,
    private val context: Context,
) {

    fun analyze(): JSONObject {
        val findings = mutableListOf<JSONObject>()
        var score = 0
        var matchedFamily = "None"
        var hardHit = false

        // 1. Blocklist ------------------------------------------------------------------------
        val blocklist = Reputation.loadBlocklist(context)
        if (ctx.sha256.lowercase() in blocklist) {
            score += Cfg.BLOCKLIST_HIT_POINTS
            hardHit = true
            matchedFamily = "Blocklisted"
            findings += finding(
                "File hash is on the known-malware blocklist (SHA-256 ${ctx.sha256.take(16)}…).",
                isWarning = true,
                category = "blocklist",
            )
        }

        // 2. Signatures ---------------------------------------------------------------------
        for (sig in Signatures.load(context)) {
            if (sig.matches(ctx.scanText)) {
                score += sig.riskWeight
                matchedFamily = sig.family
                hardHit = true
                findings += finding(
                    "Signature ${sig.id}: ${sig.name} — family ${sig.family}.",
                    isWarning = true,
                    category = "signature",
                )
            }
        }

        // 3. Repackaging / signing --------------------------------------------------------
        score += checkSigning(findings).also { if (it >= Cfg.REPACKAGE_MISMATCH_POINTS) hardHit = true }

        // 4. Heuristics -------------------------------------------------------------------
        score += detectObfuscation(findings)
        score += detectNativeLibraries(findings)
        score += detectNetworkIndicators(findings)

        if (findings.none { it.optBoolean("isWarning") }) {
            findings += finding("No known malware signatures or reputation hits.", isWarning = false)
        }

        return buildLayerJson(
            layerName = "Malware Signature Check",
            riskScore = score,
            findings = findings,
            rawData = JSONObject().apply {
                put("matchedFamily", matchedFamily)
                put("hardHit", hardHit)
                put("sha256", ctx.sha256)
                put("debugSigned", ctx.isDebugSigned)
            },
        )
    }

    // ── signing / repackaging ────────────────────────────────────────────────────────────

    private fun checkSigning(findings: MutableList<JSONObject>): Int {
        var score = 0
        val trusted = Reputation.loadTrustedCerts(context)[ctx.packageName]
        if (trusted != null) {
            val ok = ctx.signerCertSha256.any { it.lowercase() in trusted }
            if (!ok) {
                score += Cfg.REPACKAGE_MISMATCH_POINTS
                findings += finding(
                    "Package '${ctx.packageName}' is normally published by a known developer, but " +
                        "this copy is signed by a different certificate — likely repackaged.",
                    isWarning = true,
                    category = "repackaging",
                )
            }
        }
        if (ctx.isDebugSigned) {
            score += Cfg.DEBUG_SIGNED_POINTS
            findings += finding(
                "Signed with a debug certificate — not a store-published build.",
                isWarning = true,
                category = "signing",
            )
        }
        return score
    }

    // ── heuristics ───────────────────────────────────────────────────────────────────────

    private fun detectObfuscation(findings: MutableList<JSONObject>): Int {
        // Only look at text resources/assets, not raw DEX bytecode (which trips the regex by chance).
        val resourceText = ctx.scanText.removePrefix(ctx.dexText)
        val blobs = Regex("[A-Za-z0-9+/]{${Cfg.OBFUSCATION_BASE64_MIN_LEN},}={0,2}")
            .findAll(resourceText).count()
        if (blobs >= Cfg.OBFUSCATION_BASE64_MIN_COUNT) {
            findings += finding(
                "$blobs large Base64 blobs in resources/assets — possible encrypted payload.",
                isWarning = true,
                category = "obfuscation",
            )
            return Cfg.OBFUSCATION_POINTS
        }
        return 0
    }

    private fun detectNativeLibraries(findings: MutableList<JSONObject>): Int {
        val knownBad = setOf("libhook", "libinject", "libspy", "libsuperhide", "libfrida", "libsubstrate")
        var score = 0

        val flagged = ctx.nativeLibs.filter { lib -> knownBad.any { lib.contains(it, ignoreCase = true) } }
        if (flagged.isNotEmpty()) {
            score += Cfg.NATIVE_LIB_KNOWN_BAD_POINTS
            findings += finding(
                "Suspicious native library name(s): ${flagged.joinToString()}",
                isWarning = true,
                category = "native_lib",
            )
        }

        val misplaced = ctx.nativeLibs.filter { it.startsWith("assets/") || it.startsWith("res/") }
        if (misplaced.isNotEmpty()) {
            score += Cfg.NATIVE_LIB_WRONG_LOCATION_POINTS
            findings += finding(
                "Native library outside lib/ (${misplaced.first()}…) — often used to hide a payload.",
                isWarning = true,
                category = "native_lib",
            )
        }
        return score
    }

    private fun detectNetworkIndicators(findings: MutableList<JSONObject>): Int {
        var score = 0
        val content = ctx.scanText

        val ips = Regex("""(?<![\d.])(\d{1,3}\.){3}\d{1,3}:\d{2,5}""")
            .findAll(content).take(5).map { it.value }.toList()
        if (ips.isNotEmpty()) {
            score += Cfg.NETWORK_HARDCODED_IP_POINTS
            findings += finding(
                "Hardcoded IP:port address(es): ${ips.joinToString()} — possible C2 endpoint.",
                isWarning = true,
                category = "network",
            )
        }

        if (content.contains(".onion")) {
            score += Cfg.NETWORK_ONION_POINTS
            findings += finding(
                ".onion (Tor) address present — very rare in legitimate apps.",
                isWarning = true,
                category = "network",
            )
        }

        var dnsScore = 0
        for (domain in listOf("dyndns.org", "no-ip.com", "duckdns.org", "afraid.org", "ddns.net")) {
            if (content.contains(domain)) {
                dnsScore += Cfg.NETWORK_DYNAMIC_DNS_POINTS
                findings += finding(
                    "Dynamic-DNS domain: $domain — commonly abused for C2.",
                    isWarning = true,
                    category = "network",
                )
            }
        }
        score += minOf(dnsScore, Cfg.NETWORK_DYNAMIC_DNS_CAP)
        return score
    }
}
