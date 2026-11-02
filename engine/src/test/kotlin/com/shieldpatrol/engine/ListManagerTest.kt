package com.shieldpatrol.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 白名单豁免检测、黑名单强制拦截，以及名单持久化格式。 */
class ListManagerTest {

    private fun smsTrojan() = AppFeatures(
        packageName = "com.example.app", label = "x", sha256 = null, signatureHash = "sig-1",
        permissions = setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"),
        components = emptyList(), dexStrings = emptySet(),
        usesDynamicCodeLoading = false, debuggable = false, installedFromUnknownSource = false, targetSdk = 34,
    )

    @Test
    fun `白名单应用即使特征全中仍判定安全`() {
        val lists = ListManager()
        lists.addWhite("com.example.app", note = "自家测试应用")
        val r = DetectionEngine(BuiltinRules.all(), MalwareHashDb(emptyList()), lists).detect(smsTrojan())
        assertEquals(Verdict.SAFE, r.verdict)
        assertTrue(r.whitelistHit)
    }

    @Test
    fun `黑名单应用直接判定恶意并标记拦截`() {
        val lists = ListManager()
        lists.addBlack("com.example.app", note = "已知恶意")
        val r = DetectionEngine(BuiltinRules.all(), MalwareHashDb(emptyList()), lists).detect(smsTrojan())
        assertEquals(Verdict.MALICIOUS, r.verdict)
        assertTrue(r.blacklistHit)
    }

    @Test
    fun `不在名单内的应用不受影响`() {
        val lists = ListManager()
        lists.addBlack("com.other.evil", note = "")
        assertFalse(lists.isWhitelisted("com.example.app"))
        assertFalse(lists.isBlacklisted("com.example.app"))
    }

    @Test
    fun `导出后重新导入名单保持原条目`() {
        val lists = ListManager()
        lists.addWhite("com.a", note = "n1")
        lists.addBlack("com.b", note = "n2")
        val again = ListManager.import(lists.export())
        assertTrue(again.isWhitelisted("com.a"))
        assertTrue(again.isBlacklisted("com.b"))
        assertFalse(again.isWhitelisted("com.b"))
    }

    @Test
    fun `移除条目后名单不再命中`() {
        val lists = ListManager()
        lists.addBlack("com.b", note = "")
        lists.removeBlack("com.b")
        assertFalse(lists.isBlacklisted("com.b"))
    }
}
