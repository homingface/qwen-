package com.shieldpatrol.android

import android.app.Application
import com.shieldpatrol.engine.BuiltinRules
import com.shieldpatrol.engine.CustomRuleFormat
import com.shieldpatrol.engine.DetectionEngine
import com.shieldpatrol.engine.ListManager
import com.shieldpatrol.engine.MalwareHashDb
import java.io.File

/** 全局单例：加载规则库、恶意哈希库与黑白名单，供各页面与后台服务复用。 */
class ShieldApp : Application() {

    lateinit var engine: DetectionEngine
        private set
    lateinit var lists: ListManager
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        rebuild()
    }

    private fun rebuild() {
        lists = loadLists()
        engine = DetectionEngine(buildRules(), loadDb(), lists)
    }

    fun saveLists(newLists: ListManager) {
        listsFile().writeText(newLists.export())
        rebuild()
    }

    fun appendCustomRules(text: String): Int {
        val incoming = CustomRuleFormat.parse(text)
        rulesFile().appendText("\n" + CustomRuleFormat.export(incoming) + "\n")
        rebuild()
        return incoming.size
    }

    fun customRules(): List<com.shieldpatrol.engine.Rule> =
        if (rulesFile().exists()) CustomRuleFormat.parse(rulesFile().readText()) else emptyList()

    fun appendMalwareDb(text: String): Int {
        val incoming = MalwareHashDb.parse(text)
        dbFile().appendText("\n" + incoming.export() + "\n")
        rebuild()
        return incoming.size()
    }

    fun malwareDb(): MalwareHashDb = loadDb()

    fun rulesFile(): File = File(filesDir, "custom_rules.txt")
    fun dbFile(): File = File(filesDir, "malware_db.txt")
    fun listsFile(): File = File(filesDir, "lists.txt")

    private fun buildRules(): List<com.shieldpatrol.engine.Rule> =
        BuiltinRules.all() + customRules()

    private fun loadDb() = MalwareHashDb.parse(
        if (dbFile().exists()) dbFile().readText() else ""
    )

    private fun loadLists(): ListManager =
        if (listsFile().exists()) ListManager.import(listsFile().readText()) else ListManager()

    companion object {
        lateinit var instance: ShieldApp
            private set
    }
}
