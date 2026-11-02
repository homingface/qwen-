package com.shieldpatrol.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** 安装监听：新应用/覆盖安装完成后立即检测，命中恶意则通知+建议处置（阻拦链路）。 */
class PackageChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pkg = intent.data?.schemeSpecificPart ?: return
        if (pkg == context.packageName) return
        if (intent.action == Intent.ACTION_PACKAGE_ADDED || intent.action == Intent.ACTION_PACKAGE_REPLACED) {
            ScanService.scanOne(context, pkg)
        }
    }
}
