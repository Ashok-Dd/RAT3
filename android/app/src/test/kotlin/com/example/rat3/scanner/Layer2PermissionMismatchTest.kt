package com.example.rat3.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import com.example.rat3.scanner.ScannerConfig.Layer2 as Cfg

class Layer2PermissionMismatchTest {

    private fun analyze(ctx: ApkContext) = Layer2PermissionMismatch(ctx).analyze()

    @Test
    fun `no declared permissions means no mismatch and zero score`() {
        val r = analyze(fakeApkContext())
        assertEquals(0, r.getInt("riskScore"))
        assertEquals(0, r.getJSONObject("rawData").getInt("mismatchCount"))
    }

    @Test
    fun `a permission backed by a matching API call is not flagged as a mismatch`() {
        val ctx = fakeApkContext(
            permissions = setOf("android.permission.CAMERA"),
            dexText = "Landroid/hardware/camera2/CameraManager;->openCamera",
        )
        val r = analyze(ctx)
        assertEquals(0, r.getJSONObject("rawData").getInt("mismatchCount"))
    }

    @Test
    fun `a declared permission with no matching API is a low-confidence mismatch`() {
        val ctx = fakeApkContext(
            permissions = setOf("android.permission.SEND_SMS"),
            dexText = "irrelevant bytecode text",
        )
        val r = analyze(ctx)
        assertEquals(1, r.getJSONObject("rawData").getInt("mismatchCount"))
        assertEquals(Cfg.MISMATCH_POINTS, r.getInt("riskScore"))
    }

    @Test
    fun `mismatch score is capped even with many mismatched permissions`() {
        val perms = setOf(
            "android.permission.SEND_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_SMS",
            "android.permission.READ_CALL_LOG",
        )
        // 8 mismatches * 6 pts = 48, capped at MISMATCH_CAP
        val r = analyze(fakeApkContext(permissions = perms, dexText = ""))
        assertEquals(Cfg.MISMATCH_CAP, r.getInt("riskScore"))
    }

    @Test
    fun `Runtime exec in the dex text is flagged as a dangerous API`() {
        val ctx = fakeApkContext(dexText = "Ljava/lang/Runtime;->exec(Ljava/lang/String;)")
        val r = analyze(ctx)
        assertEquals(Cfg.API_RUNTIME_EXEC_POINTS, r.getInt("riskScore"))
    }

    @Test
    fun `multiple dangerous APIs stack additively`() {
        val ctx = fakeApkContext(
            dexText = "Runtime;->exec( and Ldalvik/system/DexClassLoader and Ljava/net/ServerSocket",
        )
        val r = analyze(ctx)
        val expected = Cfg.API_RUNTIME_EXEC_POINTS +
            Cfg.API_DEX_CLASSLOADER_POINTS +
            Cfg.API_SERVER_SOCKET_POINTS
        assertEquals(expected, r.getInt("riskScore"))
    }

    @Test
    fun `truncated dex adds an info finding but not a warning`() {
        val r = analyze(fakeApkContext(dexTruncated = true))
        val findings = r.getJSONArray("findings")
        val infoFinding = (0 until findings.length())
            .map { findings.getJSONObject(it) }
            .single { it.getString("message").contains("partially scanned") }
        assertTrue(!infoFinding.getBoolean("isWarning"))
    }
}
