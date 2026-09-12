package com.example.rat3.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The direct regression test for the "WhatsApp/PhonePe/Google Pay/YouTube flagged as
 * SUSPICIOUS/MALICIOUS" bug: the old scoring in `MainActivity.handleScanAllApps` added points
 * for holding permissions and doing normal background/network activity. [AppTrustEngine]
 * replaced it with the evidence/correlation rules asserted here.
 */
class AppTrustEngineTest {

    /** A Play-Store-installed, established app baseline — override only what a scenario needs. */
    private fun trustedFacts(
        installSource: String = "play_store",
        installDaysAgo: Long = 400,
        targetSdkVersion: Int = 34,
        dangerousGranted: List<String> = emptyList(),
        hasAccessibility: Boolean = false,
        hasDeviceAdmin: Boolean = false,
        hasBootPersistence: Boolean = false,
        overlayGranted: Boolean = false,
        camActiveNow: Boolean = false,
        micActiveNow: Boolean = false,
        hasNotificationAccess: Boolean = false,
        blocklistHit: Boolean = false,
        userMarkedTrusted: Boolean = false,
    ) = AppTrustEngine.AppFacts(
        installSource = installSource,
        installDaysAgo = installDaysAgo,
        targetSdkVersion = targetSdkVersion,
        dangerousGranted = dangerousGranted,
        hasAccessibility = hasAccessibility,
        hasDeviceAdmin = hasDeviceAdmin,
        hasBootPersistence = hasBootPersistence,
        overlayGranted = overlayGranted,
        camActiveNow = camActiveNow,
        micActiveNow = micActiveNow,
        hasNotificationAccess = hasNotificationAccess,
        blocklistHit = blocklistHit,
        userMarkedTrusted = userMarkedTrusted,
    )

    // ── The exact reported false positives ──────────────────────────────────

    @Test
    fun `WhatsApp-like app (camera+mic+contacts+location, heavy usage) is TRUSTED`() {
        val facts = trustedFacts(
            dangerousGranted = listOf(
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
            ),
            camActiveNow = true, // e.g. mid video call
            micActiveNow = true,
        )
        val a = AppTrustEngine.assess(facts)
        assertEquals("TRUSTED", a.trustLevel)
        assertTrue(a.evidence.isEmpty())
    }

    @Test
    fun `PhonePe-like app (SMS read for OTP, background location) is TRUSTED`() {
        val facts = trustedFacts(
            dangerousGranted = listOf(
                "android.permission.READ_SMS",
                "android.permission.CAMERA", // QR scanner
                "android.permission.ACCESS_BACKGROUND_LOCATION",
            ),
        )
        val a = AppTrustEngine.assess(facts)
        assertEquals("TRUSTED", a.trustLevel)
        // Still transparently shown, just not escalated.
        assertTrue(a.privateDataAccess.any { it.contains("SMS") })
    }

    @Test
    fun `Google Pay-like app (many high-risk permissions) is TRUSTED`() {
        val facts = trustedFacts(
            dangerousGranted = listOf(
                "android.permission.READ_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_PHONE_STATE",
            ),
        )
        val a = AppTrustEngine.assess(facts)
        assertEquals("TRUSTED", a.trustLevel)
    }

    @Test
    fun `YouTube-like app (heavy background activity, no special capabilities) is TRUSTED`() {
        val facts = trustedFacts(
            dangerousGranted = listOf("android.permission.CAMERA"),
        )
        val a = AppTrustEngine.assess(facts)
        assertEquals("TRUSTED", a.trustLevel)
    }

    @Test
    fun `plain apps with no special capabilities are always TRUSTED regardless of permission count`() {
        val manyPerms = listOf(
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_SMS",
        )
        val a = AppTrustEngine.assess(trustedFacts(dangerousGranted = manyPerms))
        assertEquals("TRUSTED", a.trustLevel)
    }

    // ── Weak indicators never escalate alone ────────────────────────────────

    @Test
    fun `sideloaded app with nothing else notable is UNKNOWN, not flagged`() {
        val a = AppTrustEngine.assess(trustedFacts(installSource = "sideloaded"))
        assertEquals("UNKNOWN", a.trustLevel)
    }

    @Test
    fun `an established app installed from a non-Play-Store storefront alone is UNKNOWN`() {
        // Only one weak indicator (install source) -- not recent, nothing else notable.
        val a = AppTrustEngine.assess(
            trustedFacts(installSource = "other:some-store", installDaysAgo = 400),
        )
        assertEquals("UNKNOWN", a.trustLevel)
    }

    @Test
    fun `two weak indicators together reach NEEDS_REVIEW`() {
        val a = AppTrustEngine.assess(
            trustedFacts(
                installSource = "sideloaded",
                installDaysAgo = 1,
                targetSdkVersion = 22,
            ),
        )
        assertEquals("NEEDS_REVIEW", a.trustLevel)
    }

    // ── Private Data Access (medium) on an untrusted app ────────────────────

    @Test
    fun `untrusted app that can read SMS reaches NEEDS_REVIEW from that alone`() {
        val a = AppTrustEngine.assess(
            trustedFacts(
                installSource = "sideloaded",
                dangerousGranted = listOf("android.permission.READ_SMS"),
            ),
        )
        assertEquals("NEEDS_REVIEW", a.trustLevel)
        assertTrue(a.evidence.any { it.contains("SMS") })
    }

    @Test
    fun `untrusted app with SMS access and notification listener access is SUSPICIOUS`() {
        val a = AppTrustEngine.assess(
            trustedFacts(
                installSource = "sideloaded",
                dangerousGranted = listOf("android.permission.READ_SMS"),
                hasNotificationAccess = true,
            ),
        )
        assertEquals("SUSPICIOUS", a.trustLevel)
    }

    // ── Strong indicators ────────────────────────────────────────────────────

    @Test
    fun `accessibility plus boot-persistence alone (no overlay) on an untrusted app is SUSPICIOUS`() {
        val a = AppTrustEngine.assess(
            trustedFacts(
                installSource = "sideloaded",
                hasAccessibility = true,
                hasBootPersistence = true,
            ),
        )
        assertEquals("SUSPICIOUS", a.trustLevel)
    }

    @Test
    fun `accessibility plus overlay on an untrusted app is the classic banker-trojan combo -- MALICIOUS_INDICATORS`() {
        // Accessibility + overlay + non-Play-Store is the exact SpyNote/Cerberus/Anubis
        // pattern, so this reaches the top tier from two closely-related strong signals
        // without needing an unrelated third one.
        val a = AppTrustEngine.assess(
            trustedFacts(
                installSource = "sideloaded",
                hasAccessibility = true,
                overlayGranted = true,
            ),
        )
        assertEquals("MALICIOUS_INDICATORS", a.trustLevel)
        assertTrue(a.evidence.any { it.contains("screen content") })
    }

    @Test
    fun `real active camera use on a freshly sideloaded app is SUSPICIOUS`() {
        val a = AppTrustEngine.assess(
            trustedFacts(installSource = "sideloaded", camActiveNow = true),
        )
        assertEquals("SUSPICIOUS", a.trustLevel)
    }

    // ── Confirmed indicator ──────────────────────────────────────────────────

    @Test
    fun `a blocklist hash hit alone is MALICIOUS_INDICATORS`() {
        val a = AppTrustEngine.assess(
            trustedFacts(installSource = "sideloaded", blocklistHit = true),
        )
        assertEquals("MALICIOUS_INDICATORS", a.trustLevel)
        assertTrue(a.evidence.first().contains("known-malicious"))
    }

    @Test
    fun `blocklistHit is ignored for a trust-baseline app`() {
        // MainActivity never actually hashes a trust-baseline app's APK (perf gate), but the
        // engine itself must also not let a stray true flag override an established
        // Play-Store app -- confirms the gate is `!isTrusted && blocklistHit`, not just `blocklistHit`.
        val a = AppTrustEngine.assess(trustedFacts(blocklistHit = true))
        assertEquals("TRUSTED", a.trustLevel)
    }

    // ── User-marked trust overrides everything else ─────────────────────────

    @Test
    fun `an app the user marked trusted is TRUSTED even with strong evidence against it`() {
        // The user's own "I trust this app" choice (rat3_test's trusted-apps allowlist) is an
        // explicit override, not just another weak signal -- it must win even over the
        // accessibility+overlay banker-trojan combo that would otherwise be MALICIOUS_INDICATORS.
        val a = AppTrustEngine.assess(
            trustedFacts(
                installSource = "sideloaded",
                hasAccessibility = true,
                overlayGranted = true,
                userMarkedTrusted = true,
            ),
        )
        assertEquals("TRUSTED", a.trustLevel)
        assertTrue(a.trustReason.contains("Trusted by you"))
        assertTrue(a.evidence.isEmpty())
    }

    @Test
    fun `user-marked trust still shows Private Data Access informationally`() {
        val a = AppTrustEngine.assess(
            trustedFacts(
                installSource = "sideloaded",
                dangerousGranted = listOf("android.permission.READ_SMS"),
                userMarkedTrusted = true,
            ),
        )
        assertEquals("TRUSTED", a.trustLevel)
        // Calm, informational -- shown regardless of trust level -- but not evidence.
        assertTrue(a.privateDataAccess.any { it.contains("SMS") })
        assertTrue(a.evidence.isEmpty())
    }
}
