package com.example.rat3.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import com.example.rat3.scanner.ScannerConfig.Layer1 as Cfg

class Layer1SafetyAnalyzerTest {

    private fun analyze(ctx: ApkContext) = Layer1SafetyAnalyzer(ctx).analyze()

    @Test
    fun `a clean app with no permissions scores zero`() {
        val r = analyze(fakeApkContext())
        assertEquals(0, r.getInt("riskScore"))
        assertFalse(r.getJSONObject("rawData").getBoolean("analysisError"))
    }

    @Test
    fun `dangerous permissions add points capped at DANGEROUS_PERM_CAP`() {
        // 10 dangerous perms * 3 pts = 30, capped at 24
        val perms = setOf(
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
        )
        val r = analyze(fakeApkContext(permissions = perms))
        assertEquals(Cfg.DANGEROUS_PERM_CAP, r.getInt("riskScore"))
    }

    @Test
    fun `accessibility service that can read screen content is heavily scored`() {
        val ctx = fakeApkContext(
            accessibility = ApkContext.AccessibilityInfo(
                declaresService = true,
                canRetrieveWindowContent = true,
                canPerformGestures = false,
                filtersKeyEvents = false,
            ),
        )
        val r = analyze(ctx)
        assertEquals(Cfg.ACCESSIBILITY_RETRIEVE_CONTENT_POINTS, r.getInt("riskScore"))
        val findings = r.getJSONArray("findings")
        val messages = (0 until findings.length()).map { findings.getJSONObject(it).getString("message") }
        assertTrue(messages.any { it.contains("read on-screen content") })
    }

    @Test
    fun `accessibility abuse plus boot-persistence adds the combo bonus`() {
        val ctx = fakeApkContext(
            permissions = setOf("android.permission.RECEIVE_BOOT_COMPLETED"),
            accessibility = ApkContext.AccessibilityInfo(
                declaresService = true,
                canRetrieveWindowContent = true,
                canPerformGestures = true,
                filtersKeyEvents = false,
            ),
        )
        val r = analyze(ctx)
        // RECEIVE_BOOT_COMPLETED is itself a "suspicious" permission (SUSPICIOUS_PERM_POINTS),
        // on top of the accessibility + persistence-combo scoring.
        val expected = Cfg.ACCESSIBILITY_RETRIEVE_CONTENT_POINTS +
            Cfg.ACCESSIBILITY_PERFORM_GESTURES_POINTS +
            Cfg.ACCESSIBILITY_PERSISTENCE_COMBO_POINTS +
            Cfg.SUSPICIOUS_PERM_POINTS
        assertEquals(expected, r.getInt("riskScore"))
    }

    @Test
    fun `device admin receiver adds fixed points and a finding`() {
        val r = analyze(fakeApkContext(hasDeviceAdminReceiver = true))
        assertEquals(Cfg.DEVICE_ADMIN_POINTS, r.getInt("riskScore"))
    }

    @Test
    fun `very old target sdk is flagged`() {
        val r = analyze(fakeApkContext(targetSdk = 19))
        assertEquals(Cfg.TARGET_SDK_VERY_OLD_POINTS, r.getInt("riskScore"))
    }

    @Test
    fun `unknown target sdk (zero) is flagged but distinctly from very-old`() {
        val r = analyze(fakeApkContext(targetSdk = 0))
        assertEquals(Cfg.TARGET_SDK_UNKNOWN_POINTS, r.getInt("riskScore"))
    }

    @Test
    fun `manifest parse failure surfaces analysisError and a warning finding`() {
        val r = analyze(fakeApkContext(manifestParseFailed = true))
        assertTrue(r.getJSONObject("rawData").getBoolean("analysisError"))
        val findings = r.getJSONArray("findings")
        val messages = (0 until findings.length()).map { findings.getJSONObject(it).getString("message") }
        assertTrue(messages.any { it.contains("could not be fully parsed") })
    }

    @Test
    fun `many exported components beyond the free allowance are scored and capped`() {
        val r = analyze(fakeApkContext(exportedComponentCount = 100))
        assertEquals(Cfg.EXPORTED_CAP, r.getInt("riskScore"))
    }
}
