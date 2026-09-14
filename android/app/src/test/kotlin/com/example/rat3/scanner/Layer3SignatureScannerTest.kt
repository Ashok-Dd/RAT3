package com.example.rat3.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import com.example.rat3.scanner.ScannerConfig.Layer3 as Cfg

/**
 * Exercises [Layer3SignatureScanner] against the *real* bundled `assets/signatures.json` via a
 * Robolectric [android.content.Context] (Reputation/Signatures read `context.assets`, so plain
 * JVM unit tests can't construct a working [Layer3SignatureScanner] without one).
 *
 * `blocklist.json` and `trusted_certs.json` ship with placeholder (all-zero) hashes only — see
 * their `_comment` fields — so the blocklist-hit and repackaging-mismatch paths are deliberately
 * NOT exercised against the real assets here; they'd require faking a context/assets pair, which
 * is more coupling than this bug-fix pass calls for. Everything else below is genuinely live.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class Layer3SignatureScannerTest {

    private val context get() = RuntimeEnvironment.getApplication()

    private fun analyze(ctx: ApkContext) = Layer3SignatureScanner(ctx, context).analyze()

    @Test
    fun `clean apk with no indicators has no hard hit`() {
        val r = analyze(fakeApkContext())
        assertFalse(r.getJSONObject("rawData").getBoolean("hardHit"))
        assertEquals("None", r.getJSONObject("rawData").getString("matchedFamily"))
    }

    @Test
    fun `a real bundled signature pattern is matched and forces a hard hit`() {
        // "AndroRAT" is RAT3-001 in the real assets/signatures.json (riskWeight 50).
        val r = analyze(fakeApkContext(scanText = "...AndroRAT marker string..."))
        val rawData = r.getJSONObject("rawData")
        assertTrue(rawData.getBoolean("hardHit"))
        assertEquals("AndroRAT", rawData.getString("matchedFamily"))
        assertTrue(r.getInt("riskScore") >= 50)
    }

    @Test
    fun `a weak generic signature match scores but does not force a hard hit`() {
        // "getSimCountryIso" is RAT3-005 (riskWeight 20, well under
        // SIGNATURE_HARD_HIT_MIN_WEIGHT) -- a SIM-country lookup used by countless
        // legitimate apps for phone-number formatting, not a distinctive malware marker.
        val r = analyze(fakeApkContext(scanText = "...getSimCountryIso()..."))
        val rawData = r.getJSONObject("rawData")
        assertEquals("BankBot", rawData.getString("matchedFamily"))
        assertFalse(rawData.getBoolean("hardHit"))
        assertEquals(20, r.getInt("riskScore"))
    }

    @Test
    fun `debug-signed apk adds fixed points and a finding, no hard hit`() {
        val r = analyze(fakeApkContext(isDebugSigned = true))
        assertEquals(Cfg.DEBUG_SIGNED_POINTS, r.getInt("riskScore"))
        assertFalse(r.getJSONObject("rawData").getBoolean("hardHit"))
        assertTrue(r.getJSONObject("rawData").getBoolean("debugSigned"))
    }

    @Test
    fun `many large base64 blobs in resources trigger the obfuscation heuristic`() {
        val blob = "A".repeat(Cfg.OBFUSCATION_BASE64_MIN_LEN)
        val resourceText = (1..Cfg.OBFUSCATION_BASE64_MIN_COUNT).joinToString(" ") { blob }
        val r = analyze(fakeApkContext(dexText = "", scanText = resourceText))
        assertEquals(Cfg.OBFUSCATION_POINTS, r.getInt("riskScore"))
    }

    @Test
    fun `a known-bad native library name is flagged`() {
        val r = analyze(fakeApkContext(nativeLibs = listOf("lib/arm64-v8a/libfrida-gadget.so")))
        assertEquals(Cfg.NATIVE_LIB_KNOWN_BAD_POINTS, r.getInt("riskScore"))
    }

    @Test
    fun `a native library outside lib slash is flagged as misplaced`() {
        val r = analyze(fakeApkContext(nativeLibs = listOf("assets/libpayload.so")))
        // Misplaced AND matches no known-bad token, so only the location penalty applies.
        assertEquals(Cfg.NATIVE_LIB_WRONG_LOCATION_POINTS, r.getInt("riskScore"))
    }

    @Test
    fun `a hardcoded IP colon port is flagged as a possible C2 endpoint`() {
        val r = analyze(fakeApkContext(scanText = "connect to 203.0.113.5:4444 now"))
        assertEquals(Cfg.NETWORK_HARDCODED_IP_POINTS, r.getInt("riskScore"))
    }

    @Test
    fun `an onion address is flagged`() {
        val r = analyze(fakeApkContext(scanText = "hidden service at abc123.onion"))
        assertEquals(Cfg.NETWORK_ONION_POINTS, r.getInt("riskScore"))
    }

    @Test
    fun `dynamic dns domains are flagged and capped`() {
        val r = analyze(
            fakeApkContext(
                scanText = "dyndns.org no-ip.com duckdns.org afraid.org ddns.net",
            ),
        )
        // 5 domains * NETWORK_DYNAMIC_DNS_POINTS would exceed the cap.
        assertEquals(Cfg.NETWORK_DYNAMIC_DNS_CAP, r.getInt("riskScore"))
    }
}
