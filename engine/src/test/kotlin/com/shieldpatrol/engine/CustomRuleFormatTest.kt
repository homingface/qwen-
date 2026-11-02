package com.shieldpatrol.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 用户可自定义/导入检测规则：行式格式解析、非法行跳过、导出回读一致。 */
class CustomRuleFormatTest {

    @Test
    fun `自定义权限组合规则可被解析并命中`() {
        val rules = CustomRuleFormat.parse("MY_SMS_RULE;TROJAN;75;permAll=android.permission.READ_SMS|android.permission.SEND_SMS")
        assertEquals(1, rules.size)
        val engine = DetectionEngine(rules, MalwareHashDb(emptyList()), ListManager())
        val r = engine.detect(AppFeatures(
            packageName = "x.y", label = "x", sha256 = null, signatureHash = "s",
            permissions = setOf("android.permission.READ_SMS", "android.permission.SEND_SMS"),
            components = emptyList(), dexStrings = emptySet(),
            usesDynamicCodeLoading = false, debuggable = false, installedFromUnknownSource = false, targetSdk = 34,
        ))
        assertEquals(Verdict.MALICIOUS, r.verdict)
        assertEquals(ThreatCategory.TROJAN, r.category)
    }

    @Test
    fun `dex字符串规则支持任意一个命中`() {
        val rules = CustomRuleFormat.parse("MINER2;MINER;80;dexAny=xmrig|stratum")
        val engine = DetectionEngine(rules, MalwareHashDb(emptyList()), ListManager())
        val r = engine.detect(AppFeatures("x.y", "x", null, "s", emptySet(), emptyList(), setOf("use xmrig miner"), false, false, false, 34))
        assertEquals(Verdict.MALICIOUS, r.verdict)
    }

    @Test
    fun `非法类别与空行被跳过`() {
        val rules = CustomRuleFormat.parse("\n# 注释\nBAD;NOTACATEGORY;10;permAll=X\nGOOD;TROJAN;10;permAll=X\n")
        assertEquals(1, rules.size)
        assertEquals("GOOD", rules[0].id)
    }

    @Test
    fun `导出再导入后规则行为不变`() {
        val parsed = CustomRuleFormat.parse("R1;BACKDOOR;60;dexAny=/system/bin/sh -c;note=反shell")
        val text = CustomRuleFormat.export(parsed)
        val reparsed = CustomRuleFormat.parse(text)
        assertEquals(1, reparsed.size)
        assertEquals("R1", reparsed[0].id)
        assertEquals(60, reparsed[0].weight)
        assertTrue(reparsed[0].match(AppFeatures("x.y", "x", null, "s", emptySet(), emptyList(), setOf("/system/bin/sh -c"), false, false, false, 34)) != null)
    }
}
