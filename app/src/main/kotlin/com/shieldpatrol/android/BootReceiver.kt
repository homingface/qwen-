package com.shieldpatrol.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** 开机后台启动一次扫描（用户可在系统设置里关闭自启）。 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            ScanService.start(context)
        }
    }
}
