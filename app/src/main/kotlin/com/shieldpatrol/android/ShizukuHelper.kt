package com.shieldpatrol.android

import android.content.Context
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import rikka.shizuku.Shizuku
import java.io.ByteArrayOutputStream

/**
 * Shizuku 提权封装：授权后可执行 force-stop / pm disable / pm uninstall，
 * 未授权或手机未装 Shizuku 时降级为"跳转系统设置页手动处置"。
 */
object ShizukuHelper {

    private const val PERMISSION_REQUEST_CODE = 1024

    fun available(): Boolean {
        return try {
            Shizuku.pingBinder()
        } catch (_: Throwable) {
            false
        }
    }

    fun granted(): Boolean {
        return try {
            available() && Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED
        } catch (_: Throwable) {
            false
        }
    }

    fun requestGrant() {
        if (!available()) return
        try {
            if (!granted()) Shizuku.requestPermission(PERMISSION_REQUEST_CODE)
        } catch (_: Throwable) {
        }
    }

    /**
     * 以 shell 身份执行命令，返回输出；失败返回 null。
     * Shizuku 各版本的 newProcess 可见性不同，用反射兼容。
     */
    private fun execShell(cmd: String): String? {
        if (!granted()) return null
        return try {
            val method = Shizuku::class.java.getDeclaredMethod(
                "newProcess",
                Array<String>::class.java,
                Array<String>::class.java,
                String::class.java,
            )
            method.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val proc = method.invoke(null, arrayOf("sh", "-c", cmd), null, null) as? Process ?: return null
            val out = ByteArrayOutputStream()
            proc.inputStream.use { it.copyTo(out) }
            proc.waitFor()
            String(out.toByteArray())
        } catch (_: Throwable) {
            null
        }
    }

    fun forceStop(context: Context, pkg: String) {
        val r = execShell("am force-stop $pkg")
        if (r != null) toast(context, "已强制停止 $pkg")
        else openAppInfo(context, pkg)
    }

    fun disable(context: Context, pkg: String) {
        val r = execShell("pm disable-user --user 0 $pkg")
        if (r != null) toast(context, "已禁用 $pkg（可在系统设置中恢复）")
        else openAppInfo(context, pkg)
    }

    fun uninstall(context: Context, pkg: String) {
        val r = execShell("pm uninstall -k --user 0 $pkg")
        if (r != null) toast(context, "已卸载 $pkg")
        else openAppInfo(context, pkg)
    }

    fun openAppInfo(context: Context, pkg: String) {
        val intent = android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
            .setData(android.net.Uri.parse("package:$pkg"))
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            context.startActivity(intent)
            toast(context, "未授权 Shizuku，请在设置页手动处理")
        } catch (_: Throwable) {
            toast(context, "无法打开应用信息页")
        }
    }

    private fun toast(context: Context, msg: String) {
        Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
    }

    /** 供 Activity 注册授权结果回调。 */
    fun registerListener(activity: AppCompatActivity) {
        try {
            Shizuku.addRequestPermissionResultListener { _, resultCode ->
                val grantedNow = resultCode == android.content.pm.PackageManager.PERMISSION_GRANTED
                Toast.makeText(activity, if (grantedNow) "Shizuku 已授权" else "Shizuku 授权被拒绝", Toast.LENGTH_SHORT).show()
            }
        } catch (_: Throwable) {
        }
    }
}
