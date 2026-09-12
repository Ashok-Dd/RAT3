package com.example.rat3.scanner

/**
 * AppTrustEngine — the evidence-based Application Assessment used by "Scan All Apps".
 *
 * Pure logic, no Android framework dependency, so it can be unit-tested directly (unlike the
 * PackageManager/AppOpsManager/UsageStatsManager calls in `MainActivity.handleScanAllApps`,
 * which only gather the [AppFacts] this class evaluates). This split mirrors [Layer1SafetyAnalyzer]
 * taking a plain [ApkContext] instead of re-parsing a manifest itself.
 *
 * Replaces a point-additive scorer that flagged WhatsApp/PhonePe/Google Pay/YouTube as
 * SUSPICIOUS/MALICIOUS purely for holding permissions and doing normal background/network
 * activity — see `MainActivity.handleScanAllApps`'s doc comment for the full history.
 *
 *   TRUST BASELINE — a Play-Store-installed, established app with no accessibility+
 *     overlay/admin/persistence combo is always TRUSTED, no matter its permissions or activity.
 *     An app the user has explicitly marked trusted (see [UserTrustStore]) is also TRUSTED
 *     immediately, regardless of install source — this is the user overriding RAT3's own
 *     judgment, not RAT3 vouching for the app itself.
 *   WEAK indicators (sideloaded, recent install, old target SDK…) never escalate alone.
 *   MEDIUM indicators (Private Data Access: can read SMS / notifications / on-screen content)
 *     reach NEEDS_REVIEW alone on an untrusted app, SUSPICIOUS with a second one.
 *   STRONG indicators (accessibility+persistence combo, real active camera/mic on an untrusted
 *     app, overlay+accessibility, device-admin) reach SUSPICIOUS alone, MALICIOUS_INDICATORS
 *     with a second one.
 *   CONFIRMED indicator (installed APK's SHA-256 matches the blocklist) is the only path to
 *     MALICIOUS_INDICATORS on its own.
 */
object AppTrustEngine {

    /** Everything the engine needs to know about one installed app. Gathered by the caller
     *  (MainActivity) from real Android APIs — this class does not know where it came from. */
    data class AppFacts(
        val installSource: String, // "play_store" | "sideloaded" | "unknown" | "other:xxx"
        val installDaysAgo: Long,
        val targetSdkVersion: Int,
        val dangerousGranted: List<String>,
        val hasAccessibility: Boolean,
        val hasDeviceAdmin: Boolean,
        val hasBootPersistence: Boolean,
        val overlayGranted: Boolean,
        val camActiveNow: Boolean,
        val micActiveNow: Boolean,
        val hasNotificationAccess: Boolean,
        val blocklistHit: Boolean,
        val userMarkedTrusted: Boolean = false,
    )

    data class Assessment(
        val trustLevel: String,
        val trustReason: String,
        val evidence: List<String>,
        val privateDataAccess: List<String>,
        val sortWeight: Int,
    )

    private data class Evidence(val severity: String, val text: String)

    fun assess(f: AppFacts): Assessment {
        val isSideloaded = f.installSource == "sideloaded"
        val isPlayStoreInstall = f.installSource == "play_store"
        val isRecentInstall = f.installDaysAgo < 7

        val abuseCombo = f.hasAccessibility &&
            (f.overlayGranted || f.hasDeviceAdmin || f.hasBootPersistence)
        val isTrusted = f.userMarkedTrusted || (isPlayStoreInstall && !isRecentInstall && !abuseCombo)

        val evidence = mutableListOf<Evidence>()
        val privateDataAccess = mutableListOf<String>()

        if (!isTrusted) {
            if (isSideloaded) {
                evidence += Evidence("weak", "Installed outside Play Store")
            } else if (f.installSource.startsWith("other:")) {
                evidence += Evidence("weak", "Installed by ${f.installSource}, not Play Store")
            }
            if (isRecentInstall) evidence += Evidence("weak", "Installed ${f.installDaysAgo} day(s) ago")
            if (f.targetSdkVersion < 26) evidence += Evidence("weak", "Targets old Android API ${f.targetSdkVersion}")
        }

        // Private Data Access — always recorded so trusted apps show the transparent
        // "expected use" framing too, not just untrusted ones.
        val hasSms = "android.permission.READ_SMS" in f.dangerousGranted ||
            "android.permission.RECEIVE_SMS" in f.dangerousGranted
        if (hasSms) {
            privateDataAccess += "Can read SMS messages"
            if (!isTrusted) evidence += Evidence("medium", "Can read your SMS messages")
        }
        if (f.hasNotificationAccess) {
            privateDataAccess += "Can read your notifications, including message/email previews from other apps"
            if (!isTrusted) evidence += Evidence("medium", "Can read your notifications, including message/email previews")
        }
        if (f.hasAccessibility) {
            privateDataAccess += "Can read anything shown on screen, including emails and messages you view"
            if (!isTrusted) evidence += Evidence("medium", "Accessibility service can read on-screen content")
        }
        if ("android.permission.ACCESS_BACKGROUND_LOCATION" in f.dangerousGranted && !isTrusted) {
            evidence += Evidence("medium", "Tracks location in the background")
        }

        if (!isTrusted) {
            if (abuseCombo) {
                evidence += Evidence(
                    "strong",
                    "Accessibility service combined with overlay/device-admin/boot-persistence — " +
                        "a classic RAT/banking-trojan pattern",
                )
            }
            if (f.camActiveNow || f.micActiveNow) {
                evidence += Evidence("strong", "Camera or microphone is in active use right now")
            }
            if (f.overlayGranted && f.hasAccessibility) {
                evidence += Evidence("strong", "Can draw over other apps AND read screen content")
            }
            if (f.hasDeviceAdmin) {
                evidence += Evidence("strong", "Has Device Administrator privileges")
            }
        }

        val confirmed = if (!isTrusted && f.blocklistHit) {
            "Installed app's file matches a known-malicious file hash"
        } else null

        val strongCount = evidence.count { it.severity == "strong" }
        val mediumCount = evidence.count { it.severity == "medium" }
        val weakCount = evidence.count { it.severity == "weak" }

        val trustLevel = when {
            confirmed != null -> "MALICIOUS_INDICATORS"
            isTrusted -> "TRUSTED"
            strongCount >= 2 -> "MALICIOUS_INDICATORS"
            strongCount == 1 -> "SUSPICIOUS"
            mediumCount >= 2 -> "SUSPICIOUS"
            mediumCount == 1 -> "NEEDS_REVIEW"
            weakCount >= 2 -> "NEEDS_REVIEW"
            else -> "UNKNOWN"
        }
        val sortWeight = when (trustLevel) {
            "MALICIOUS_INDICATORS" -> 4
            "SUSPICIOUS" -> 3
            "NEEDS_REVIEW" -> 2
            "UNKNOWN" -> 1
            else -> 0
        }
        val evidenceText = (confirmed?.let { listOf(it) } ?: emptyList()) + evidence.map { it.text }
        val trustReason = when {
            f.userMarkedTrusted -> "Trusted by you — added to your trusted apps list, scanning skipped"
            isTrusted -> "Trusted — installed from Play Store, established, no privileged capability combination detected"
            evidenceText.isEmpty() -> "Not installed from Play Store, but no other indicators found"
            else -> evidenceText.first()
        }

        return Assessment(
            trustLevel = trustLevel,
            trustReason = trustReason,
            evidence = evidenceText,
            privateDataAccess = privateDataAccess,
            sortWeight = sortWeight,
        )
    }
}
