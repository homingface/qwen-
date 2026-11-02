package com.shieldpatrol.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.shieldpatrol.engine.AppFeatures
import com.shieldpatrol.engine.Verdict
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** 前台扫描服务：遍历已安装应用 → 采集特征 → 引擎判定 → 更新全局结果。 */
class ScanService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTI_ID, buildNotification("正在扫描", ""))
        scope.launch {
            runFullScan(this@ScanService)
            stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }

    companion object {
        private const val CHANNEL = "scan"
        private const val NOTI_ID = 1001
        const val ACTION_SCAN_ONE = "com.shieldpatrol.SCAN_ONE"
        const val EXTRA_PKG = "pkg"

        fun start(context: Context) {
            ensureChannel(context)
            val i = Intent(context, ScanService::class.java)
            context.startForegroundService(i)
        }

        /** 安装监听触发：仅扫描新装包并弹结果通知。 */
        fun scanOne(context: Context, pkg: String) {
            ensureChannel(context)
            val i = Intent(context, ScanService::class.java).setAction(ACTION_SCAN_ONE).putExtra(EXTRA_PKG, pkg)
            context.startForegroundService(i)
        }

        private fun ensureChannel(context: Context) {
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "扫描", NotificationManager.IMPORTANCE_HIGH)
            )
        }

        fun notifyResult(context: Context, title: String, body: String, malicious: Boolean) {
            ensureChannel(context)
            val pi = PendingIntent.getActivity(
                context, 0,
                Intent(context, ScanActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                PendingIntent.FLAG_IMMUTABLE
            )
            val n = NotificationCompat.Builder(context, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setAutoCancel(true)
                .setPriority(if (malicious) Notification.PRIORITY_MAX else Notification.PRIORITY_DEFAULT)
                .setContentIntent(pi)
                .build()
            context.getSystemService(NotificationManager::class.java)
                .notify(System.identityHashCode(body).and(0xFFFF) + 2000, n)
        }

        fun runFullScan(context: Context) {
            val app = context.applicationContext as ShieldApp
            val collector = FeatureCollector(context)
            val probes = app.engine.allDexProbes()
            val pkgs = collector.allInstalledPackages()
            val items = mutableListOf<ScanState.Item>()
            ScanState.setProgress(true, pkgs.size, 0, "")
            pkgs.forEachIndexed { idx, pkg ->
                ScanState.setProgress(true, pkgs.size, idx + 1, pkg)
                val f = collector.collect(pkg, probes) ?: return@forEachIndexed
                val r = app.engine.detect(f)
                items.add(ScanState.Item(f, r))
                if (r.verdict == Verdict.MALICIOUS) {
                    notifyResult(context, "发现恶意应用：${f.label}",
                        "类别：${r.category?.label ?: "未知"} 风险分：${r.score}", true)
                }
            }
            ScanState.setItems(items)
            ScanState.setProgress(false, pkgs.size, pkgs.size, "")
            notifyResult(context, "扫描完成", "共扫描 ${pkgs.size} 个应用：" +
                "恶意 ${items.count { it.result.verdict == Verdict.MALICIOUS }}，" +
                "可疑 ${items.count { it.result.verdict == Verdict.SUSPICIOUS }}", false)
        }

        fun scanSingle(context: Context, pkg: String): AppFeatures? {
            val app = context.applicationContext as ShieldApp
            val f = FeatureCollector(context).collect(pkg, app.engine.allDexProbes()) ?: return null
            val r = app.engine.detect(f)
            if (r.verdict == Verdict.MALICIOUS) {
                notifyResult(context, "拦截：检测到恶意应用 ${f.label}",
                    "类别：${r.category?.label} 风险分：${r.score}。点击查看详情并处置。", true)
            } else if (r.verdict == Verdict.SUSPICIOUS) {
                notifyResult(context, "可疑应用：${f.label}", "风险分：${r.score}", false)
            }
            return f
        }
    }

    private fun buildNotification(title: String, body: String): Notification =
        NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setContentTitle(title)
            .setContentText(body)
            .setOngoing(true)
            .build()
}
