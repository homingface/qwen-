package com.shieldpatrol.android

import android.app.AlertDialog
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.shieldpatrol.engine.BuiltinRules
import com.shieldpatrol.engine.CustomRuleFormat

/** 规则库管理页：查看内置/自定义规则数量、导入导出规则与恶意库。 */
class RulesActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_rules)

        findViewById<Button>(R.id.btnImportRules).setOnClickListener {
            showTextDialog("导入规则（每行：ID;类别;权重;条件）") { text ->
                val n = ShieldApp.instance.appendCustomRules(text)
                msg("已导入 $n 条自定义规则")
                refresh()
            }
        }
        findViewById<Button>(R.id.btnExportRules).setOnClickListener {
            showTextDialog("当前自定义规则（可复制保存）", CustomRuleFormat.export(ShieldApp.instance.customRules()), readOnly = true)
        }
        findViewById<Button>(R.id.btnImportDb).setOnClickListener {
            showTextDialog("导入恶意库（每行：哈希;类型;类别;名称）") { text ->
                val n = ShieldApp.instance.appendMalwareDb(text)
                msg("已导入 $n 条恶意库记录")
                refresh()
            }
        }
        findViewById<Button>(R.id.btnExportDb).setOnClickListener {
            showTextDialog("当前恶意库", ShieldApp.instance.malwareDb().export(), readOnly = true)
        }
        refresh()
    }

    private fun refresh() {
        val builtin = BuiltinRules.all().size
        val custom = ShieldApp.instance.customRules().size
        val db = ShieldApp.instance.malwareDb().size()
        findViewById<TextView>(R.id.tvRuleStats).text =
            "内置行为规则：$builtin 条\n自定义规则：$custom 条\n本地恶意哈希库：$db 条\n\n" +
                "格式说明：\n规则 ID;类别(TROJAN/RANSOMWARE/ADWARE/PRIVACY_STEALER/MINER/BACKDOOR/GENERIC);权重0-100;" +
                "条件（permAll=a|b / permAny=a|b / dexAny=a|b / compAny=SERVICE:sms / flag=dynamic|debug|unknown / maxTargetSdk=n）\n" +
                "恶意库 哈希;类型(APK/SIG);类别;名称"
    }

    private fun msg(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()

    private fun showTextDialog(title: String, prefill: String = "", readOnly: Boolean = false, onSave: ((String) -> Unit)? = null) {
        val et = EditText(this).apply {
            setText(prefill)
            if (readOnly) isFocusable = false
            setPadding(24, 24, 24, 24)
        }
        val builder = AlertDialog.Builder(this).setTitle(title).setView(et)
        if (onSave != null) {
            builder.setPositiveButton("导入") { _, _ -> onSave(et.text.toString()) }
        }
        builder.setNegativeButton("关闭", null).show()
    }
}
