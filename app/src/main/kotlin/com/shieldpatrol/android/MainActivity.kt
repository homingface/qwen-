package com.shieldpatrol.android

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.shieldpatrol.engine.Verdict
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<Button>(R.id.btnScan).setOnClickListener {
            ScanService.start(this)
        }
        findViewById<Button>(R.id.btnOpenScan).setOnClickListener {
            startActivity(Intent(this, ScanActivity::class.java))
        }
        findViewById<Button>(R.id.btnLists).setOnClickListener {
            startActivity(Intent(this, ListsActivity::class.java))
        }
        findViewById<Button>(R.id.btnRules).setOnClickListener {
            startActivity(Intent(this, RulesActivity::class.java))
        }
        findViewById<Button>(R.id.btnGrantShizuku).setOnClickListener {
            if (ShizukuHelper.available()) {
                ShizukuHelper.registerListener(this)
                ShizukuHelper.requestGrant()
            } else {
                Toast.makeText(
                    this,
                    "未检测到 Shizuku：请先安装并启动 Shizuku；未授权时应用仍可扫描与告警",
                    Toast.LENGTH_LONG
                ).show()
            }
        }

        lifecycleScope.launch {
            ScanState.progress.collectLatest { p ->
                findViewById<TextView>(R.id.tvProtection).text =
                    if (p.running) getString(R.string.scanning) + " ${p.done}/${p.total}\n${p.current}"
                    else getString(R.string.protection_on)
            }
        }
        lifecycleScope.launch {
            ScanState.items.collectLatest { items ->
                findViewById<TextView>(R.id.tvCountSafe).text =
                    "${getString(R.string.safe_apps)}\n" + items.count { it.result.verdict == Verdict.SAFE }
                findViewById<TextView>(R.id.tvCountSuspicious).text =
                    "${getString(R.string.suspicious_apps)}\n" + items.count { it.result.verdict == Verdict.SUSPICIOUS }
                findViewById<TextView>(R.id.tvCountMalicious).text =
                    "${getString(R.string.malicious_apps)}\n" + items.count { it.result.verdict == Verdict.MALICIOUS }
            }
        }
        lifecycleScope.launch {
            delay(500)
            findViewById<TextView>(R.id.tvShizuku).text =
                if (ShizukuHelper.granted()) getString(R.string.shizuku_active) else getString(R.string.shizuku_inactive)
        }
    }
}
