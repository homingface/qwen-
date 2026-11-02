package com.shieldpatrol.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 检测引擎核心行为：规则命中、权重累计、判定分级、恶意类别归类。
 * 阈值约定：score >= 70 → MALICIOUS；40..69 → SUSPICIOUS；<40 → SAFE。
 */
class RuleEngineTest {

    private fun engine() = DetectionEngine(BuiltinRules.all(), MalwareHashDb(emptyList()), ListManager())

    private fun feats(
        pkg: String = "com.example.app",
        perms: Set<String> = emptySet(),
        components: List<ComponentInfo> = emptyList(),
        dex: Set<String> = emptySet(),
        dynamic: Boolean = false,
        debuggable: Boolean = false,
        unknownSource: Boolean = false,
    ) = AppFeatures(
        packageName = pkg,
        label = "test",
        sha256 = null,
        signatureHash = "sig-$pkg",
        permissions = perms,
        components = components,
        dexStrings = dex,
        usesDynamicCodeLoading = dynamic,
        debuggable = debuggable,
        installedFromUnknownSource = unknownSource,
        targetSdk = 34,
    )

    @Test
    fun `普通联网游戏应用判定为安全`() {
        val r = engine().detect(feats(perms = setOf("android.permission.INTERNET", "android.permission.VIBRATE", "com.android.vending.BILLING")))
        assertEquals(Verdict.SAFE, r.verdict)
        assertTrue(r.findings.isEmpty())
    }

    @Test
    fun `短信全读写加静默发送组合判定为恶意木马`() {
        val r = engine().detect(feats(perms = setOf(
            "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS", "android.permission.INTERNET",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        )))
        assertEquals(Verdict.MALICIOUS, r.verdict)
        assertEquals(ThreatCategory.TROJAN, r.category)
        assertTrue(r.score >= 70)
    }

    @Test
    fun `无障碍服务配合敏感权限判定为隐私窃取`() {
        val r = engine().detect(feats(
            perms = setOf("android.permission.READ_SMS"),
            components = listOf(ComponentInfo("com.x.AccessSvc", ComponentType.SERVICE, false, "android.permission.BIND_ACCESSIBILITY_SERVICE")),
        ))
        assertEquals(Verdict.MALICIOUS, r.verdict)
        assertEquals(ThreatCategory.PRIVACY_STEALER, r.category)
    }

    @Test
    fun `勒索特征字符串判定为勒索软件`() {
        val r = engine().detect(feats(
            perms = setOf("android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.INTERNET"),
            dex = setOf("HOWTORECOVERFILES.txt", "aes_encrypt"),
        ))
        assertEquals(Verdict.MALICIOUS, r.verdict)
        assertEquals(ThreatCategory.RANSOMWARE, r.category)
    }

    @Test
    fun `矿池字符串判定为挖矿木马`() {
        val r = engine().detect(feats(
            perms = setOf("android.permission.INTERNET", "android.permission.WAKE_LOCK"),
            dex = setOf("stratum+tcp://pool.example", "xmrig"),
        ))
        assertEquals(Verdict.MALICIOUS, r.verdict)
        assertEquals(ThreatCategory.MINER, r.category)
    }

    @Test
    fun `悬浮窗劫持组合判定为广告劫持`() {
        val r = engine().detect(feats(
            perms = setOf("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.QUERY_ALL_PACKAGES", "android.permission.INTERNET"),
            dex = setOf("TYPE_APPLICATION_OVERLAY"),
        ))
        assertEquals(Verdict.MALICIOUS, r.verdict)
        assertEquals(ThreatCategory.ADWARE, r.category)
    }

    @Test
    fun `动态加载加网络权限累计为可疑`() {
        val r = engine().detect(feats(
            perms = setOf("android.permission.INTERNET"),
            dynamic = true,
        ))
        assertEquals(Verdict.SUSPICIOUS, r.verdict)
        assertEquals(ThreatCategory.BACKDOOR, r.category)
    }

    @Test
    fun `多个弱特征累计越过可疑阈值`() {
        val r = engine().detect(feats(
            perms = setOf("android.permission.INTERNET"),
            dex = setOf("su -c"),
            debuggable = true,
            unknownSource = true,
        ))
        assertTrue(r.score >= 40)
        assertEquals(Verdict.SUSPICIOUS, r.verdict)
    }

    @Test
    fun `反向shell特征判定为后门`() {
        val r = engine().detect(feats(
            perms = setOf("android.permission.INTERNET"),
            dex = setOf("/system/bin/sh -c"),
            dynamic = true,
        ))
        assertEquals(Verdict.MALICIOUS, r.verdict)
        assertEquals(ThreatCategory.BACKDOOR, r.category)
    }

    @Test
    fun `类别取所有命中规则中权重最高者`() {
        val r = engine().detect(feats(
            perms = setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"),
            dex = setOf("xmrig"),
        ))
        // 挖矿 80 分 > 短信木马 70 分
        assertEquals(ThreatCategory.MINER, r.category)
    }
}
