package com.shieldpatrol.android

import android.app.AlertDialog
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.shieldpatrol.engine.ListEntry
import com.shieldpatrol.engine.ListKind

/** 黑白名单管理页：查看、手动添加、长按移除。 */
class ListsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_lists)
        refresh()
        findViewById<Button>(R.id.btnAddEntry).setOnClickListener { showAddDialog() }
    }

    private fun refresh() {
        val lists = ShieldApp.instance.lists
        val whiteView = findViewById<TextView>(R.id.tvWhiteList)
        val blackView = findViewById<TextView>(R.id.tvBlackList)
        whiteView.text = lists.entries(ListKind.WHITE).joinToString("\n") { "${it.packageName}（${it.note}）" }.ifEmpty { "（空）" }
        blackView.text = lists.entries(ListKind.BLACK).joinToString("\n") { "${it.packageName}（${it.note}）" }.ifEmpty { "（空）" }
        whiteView.setOnLongClickListener { promptRemove(lists.entries(ListKind.WHITE), true); true }
        blackView.setOnLongClickListener { promptRemove(lists.entries(ListKind.BLACK), false); true }
    }

    private fun showAddDialog() {
        val view = EditText(this).apply {
            hint = "应用包名（可在详情页长按列表项移除）"
            setPadding(24, 24, 24, 24)
        }
        AlertDialog.Builder(this)
            .setTitle("输入应用包名")
            .setView(view)
            .setPositiveButton("下一步") { _, _ ->
                val pkg = view.text.toString().trim()
                if (pkg.isEmpty()) return@setPositiveButton
                AlertDialog.Builder(this)
                    .setTitle("添加到哪个名单？")
                    .setItems(arrayOf(getString(R.string.whitelist), getString(R.string.blacklist))) { _, which ->
                        val lists = ShieldApp.instance.lists
                        if (which == 0) lists.addWhite(pkg, note = "手动") else lists.addBlack(pkg, note = "手动")
                        ShieldApp.instance.saveLists(lists)
                        refresh()
                    }
                    .show()
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun promptRemove(entries: List<ListEntry>, white: Boolean) {
        if (entries.isEmpty()) return
        AlertDialog.Builder(this)
            .setTitle(if (white) "移除白名单条目" else "移除黑名单条目")
            .setItems(entries.map { it.packageName }.toTypedArray()) { _, i ->
                val lists = ShieldApp.instance.lists
                val pkg = entries[i].packageName
                if (white) lists.removeWhite(pkg) else lists.removeBlack(pkg)
                ShieldApp.instance.saveLists(lists)
                refresh()
            }
            .show()
    }
}
