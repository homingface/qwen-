package com.shieldpatrol.android

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.shieldpatrol.engine.DetectionResult
import com.shieldpatrol.engine.Verdict

/** 单个应用的检测详情与处置：强停/禁用/卸载（Shizuku），加白/加黑。 */
class AppDetailActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PKG = "pkg"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_detail)
        val pkg = intent.getStringExtra(EXTRA_PKG) ?: run { finish(); return }

        val item = ScanState.items.value.firstOrNull { it.features.packageName == pkg }
        val detail = findViewById<TextView>(R.id.tvDetail)
        if (item == null) {
            detail.text = "尚无 $pkg 的扫描结果，请先执行扫描。"
            findViewById<View>(R.id.layoutActions).visibility = View.GONE
            return
        }

        detail.text = buildString {
            appendLine("应用：${item.features.label}")
            appendLine("包名：$pkg")
            appendLine("判定：${verdictText(item.result)}  分数：${item.result.score}")
            item.result.category?.let { appendLine("类别：${it.label}") }
            if (item.result.whitelistHit) appendLine("（白名单豁免）")
            if (item.result.blacklistHit) appendLine("（黑名单拦截）")
            appendLine()
            appendLine("风险明细：")
            if (item.result.findings.isEmpty()) appendLine(getString(R.string.no_findings))
            item.result.findings.forEach { f ->
                appendLine("· [${f.ruleId}] ${f.detail}（+${f.weight}）")
            }
            appendLine()
            appendLine("权限（${item.features.permissions.size}）：")
            item.features.permissions.sorted().forEach { appendLine("  $it") }
        }

        findViewById<Button>(R.id.btnForceStop).setOnClickListener { ShizukuHelper.forceStop(this, pkg) }
        findViewById<Button>(R.id.btnDisable).setOnClickListener { ShizukuHelper.disable(this, pkg) }
        findViewById<Button>(R.id.btnUninstall).setOnClickListener { ShizukuHelper.uninstall(this, pkg) }
        findViewById<Button>(R.id.btnAddWhite).setOnClickListener { addToList(pkg, true) }
        findViewById<Button>(R.id.btnAddBlack).setOnClickListener { addToList(pkg, false) }
    }

    private fun addToList(pkg: String, white: Boolean) {
        val lists = ShieldApp.instance.lists
        if (white) {
            lists.addWhite(pkg, note = "手动加入")
            if (lists.isBlacklisted(pkg)) lists.removeBlack(pkg)
        } else {
            lists.addBlack(pkg, note = "手动加入")
            if (lists.isWhitelisted(pkg)) lists.removeWhite(pkg)
        }
        ShieldApp.instance.saveLists(lists)
        Toast.makeText(this, if (white) "已加入白名单" else "已加入黑名单", Toast.LENGTH_SHORT).show()
        finish()
    }

    private fun verdictText(r: DetectionResult): String = when (r.verdict) {
        Verdict.MALICIOUS -> "恶意"
        Verdict.SUSPICIOUS -> "可疑"
        Verdict.SAFE -> "安全"
    }
}
