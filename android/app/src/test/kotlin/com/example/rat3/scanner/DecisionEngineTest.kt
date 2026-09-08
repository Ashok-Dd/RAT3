package com.example.rat3.scanner

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DecisionEngineTest {

    private fun layer(score: Int, error: Boolean = false, hardHit: Boolean = false): JSONObject =
        JSONObject().apply {
            put("layerName", "L")
            put("riskScore", score)
            put("findings", JSONArray())
            put("rawData", JSONObject().apply {
                put("analysisError", error)
                put("hardHit", hardHit)
            })
        }

    private fun verdict(l1: Int, l2: Int, l3: Int, l4: Int, hardHit: Boolean = false): JSONObject =
        DecisionEngine("/x.apk", layer(l1), layer(l2), layer(l3, hardHit = hardHit), layer(l4))
            .computeVerdict()

    @Test
    fun `all-clean apk is SAFE`() {
        val r = verdict(0, 0, 0, 0)
        assertEquals("SAFE", r.getString("verdict"))
        assertEquals(0, r.getInt("overallRiskScore"))
    }

    @Test
    fun `moderate scores land in SUSPICIOUS band`() {
        // weighted = 40*.2 + 40*.2 + 40*.35 + 40*.25 = 40
        val r = verdict(40, 40, 40, 40)
        assertEquals("SUSPICIOUS", r.getString("verdict"))
        assertEquals(40, r.getInt("overallRiskScore"))
    }

    @Test
    fun `high scores are MALICIOUS`() {
        val r = verdict(80, 80, 90, 85)
        assertEquals("MALICIOUS", r.getString("verdict"))
    }

    @Test
    fun `layer 3 hard hit escalates an otherwise low score`() {
        val r = verdict(0, 0, 20, 0, hardHit = true)
        assertEquals("MALICIOUS", r.getString("verdict"))
        assertTrue(r.getInt("overallRiskScore") >= ScannerConfig.Decision.ESCALATION_MIN_SCORE)
        assertTrue(r.getJSONObject("scoreBreakdown").getBoolean("escalated"))
    }

    @Test
    fun `an errored layer alone cannot force MALICIOUS`() {
        val engine = DecisionEngine(
            "/x.apk",
            layer(50, error = true), // e.g. manifest parse failed
            layer(0),
            layer(0),
            layer(0),
        )
        val r = engine.computeVerdict()
        assertEquals("SAFE", r.getString("verdict"))
        assertTrue(r.getString("summary").contains("partial data"))
    }
}
