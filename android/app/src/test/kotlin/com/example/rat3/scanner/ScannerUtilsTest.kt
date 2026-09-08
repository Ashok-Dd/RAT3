package com.example.rat3.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScannerUtilsTest {

    @Test
    fun `finding omits category when null`() {
        val f = finding("hello", isWarning = true)
        assertEquals("hello", f.getString("message"))
        assertTrue(f.getBoolean("isWarning"))
        assertFalse(f.has("category"))
    }

    @Test
    fun `finding keeps category when provided`() {
        val f = finding("x", isWarning = false, category = "network")
        assertEquals("network", f.getString("category"))
    }

    @Test
    fun `buildLayerJson clamps risk score to the 0 to 100 range`() {
        val over = buildLayerJson("L", riskScore = 250, findings = emptyList())
        val under = buildLayerJson("L", riskScore = -10, findings = emptyList())
        assertEquals(100, over.getInt("riskScore"))
        assertEquals(0, under.getInt("riskScore"))
    }

    @Test
    fun `buildLayerJson records analysisError in rawData`() {
        val ok = buildLayerJson("L", 0, emptyList())
        val bad = buildLayerJson("L", 0, emptyList(), analysisError = true)
        assertFalse(ok.getJSONObject("rawData").getBoolean("analysisError"))
        assertTrue(bad.getJSONObject("rawData").getBoolean("analysisError"))
    }

    @Test
    fun `signature parse round-trips and defaults match asset count`() {
        val json = """[{"id":"T1","name":"n","family":"f","pattern":"abc","isRegex":false}]"""
        val sigs = Signatures.parse(json)
        assertEquals(1, sigs.size)
        assertEquals(20, sigs[0].riskWeight) // default
        assertTrue(sigs[0].matches("xx abc yy"))
        assertFalse(sigs[0].matches("xx def yy"))
        assertEquals(10, Signatures.DEFAULTS.size)
    }

    @Test
    fun `malformed regex signature never throws`() {
        val sig = Signature("T", "n", "f", "(unclosed", isRegex = true, riskWeight = 10)
        assertFalse(sig.matches("anything"))
    }

    @Test
    fun `known permission classification is stable`() {
        assertTrue("android.permission.SEND_SMS" in KnownPermissions.DANGEROUS)
        assertTrue("android.permission.BIND_ACCESSIBILITY_SERVICE" in KnownPermissions.SUSPICIOUS)
        assertEquals("SEND_SMS", KnownPermissions.shortName("android.permission.SEND_SMS"))
    }
}
