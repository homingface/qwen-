package com.shieldpatrol.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** 本地恶意软件哈希库：命中即恶意，支持文本格式导入导出。 */
class HashDbTest {

    @Test
    fun `APK完整哈希命中直接判定恶意`() {
        val db = MalwareHashDb.parse("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;APK;TROJAN;FakeApp样本")
        val engine = DetectionEngine(BuiltinRules.all(), db, ListManager())
        val r = engine.detect(AppFeatures(
            packageName = "com.example.app", label = "x",
            sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            signatureHash = "sig-1", permissions = setOf("android.permission.INTERNET"),
            components = emptyList(), dexStrings = emptySet(),
            usesDynamicCodeLoading = false, debuggable = false, installedFromUnknownSource = false, targetSdk = 34,
        ))
        assertEquals(Verdict.MALICIOUS, r.verdict)
        assertEquals(ThreatCategory.TROJAN, r.category)
        assertEquals(100, r.score)
    }

    @Test
    fun `签名哈希命中同样判定恶意`() {
        val db = MalwareHashDb.parse("deadbeef0000;SIG;RANSOMWARE;勒索家族签名")
        assertEquals(ThreatCategory.RANSOMWARE, db.match(sha256 = null, signatureHash = "deadbeef0000")?.category)
    }

    @Test
    fun `未命中返回空`() {
        val db = MalwareHashDb.parse("aaaa;APK;GENERIC;n")
        assertNull(db.match(sha256 = "bbbb", signatureHash = "cccc"))
    }

    @Test
    fun `解析时跳过注释与格式错误行`() {
        val db = MalwareHashDb.parse("# 注释行\n\nbadline\n1111;APK;TROJAN;ok\n")
        assertEquals(1, db.size())
    }

    @Test
    fun `导出文本可重新解析且结果一致`() {
        val db = MalwareHashDb.parse("2222;APK;MINER;m\n3333;SIG;BACKDOOR;b\n")
        val again = MalwareHashDb.parse(db.export())
        assertEquals(ThreatCategory.BACKDOOR, again.match(sha256 = null, signatureHash = "3333")?.category)
        assertEquals(ThreatCategory.MINER, again.match(sha256 = "2222", signatureHash = null)?.category)
    }
}
