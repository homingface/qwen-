package com.shieldpatrol.android

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.shieldpatrol.engine.AppFeatures
import com.shieldpatrol.engine.ComponentInfo
import com.shieldpatrol.engine.ComponentType
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * 从已安装应用采集检测引擎需要的特征：权限、导出组件、Dex 特征串、签名与 APK 哈希等。
 */
class FeatureCollector(private val context: Context) {

    /** probeStrings：规则库中出现过的全部 Dex 特征字符串，命中哪些收集哪些。 */
    fun collect(pkg: String, probeStrings: Set<String>): AppFeatures? {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES or
                PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or
                PackageManager.MATCH_UNINSTALLED_PACKAGES
        val info: PackageInfo = try {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(pkg, flags)
        } catch (_: Exception) {
            null
        } ?: return null
        val appInfo = info.applicationInfo ?: return null

        val label = pm.getApplicationLabel(appInfo).toString()
        val apkPath = appInfo.sourceDir
        val sha = apkPath?.let { sha256OfFile(File(it)) }
        val sigHash = signatureHash(info, pkg)

        val perms = info.requestedPermissions?.toSet() ?: emptySet()
        val components = collectComponents(info)
        val dexHits = scanDex(apkPath, probeStrings)
        val dynamic = dexHits.contains("dalvik.system.DexClassLoader") ||
                dexHits.contains("dalvik.system.DexCode")
        val debuggable = (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val unknown = isUnknownSource(pkg)
        val targetSdk = appInfo.targetSdkVersion

        return AppFeatures(
            packageName = pkg,
            label = label,
            sha256 = sha,
            signatureHash = sigHash,
            permissions = perms,
            components = components,
            dexStrings = dexHits,
            usesDynamicCodeLoading = dynamic,
            debuggable = debuggable,
            installedFromUnknownSource = unknown,
            targetSdk = targetSdk,
        )
    }

    fun allInstalledPackages(): List<String> {
        val pm = context.packageManager
        return pm.getInstalledPackages(0).mapNotNull { it.packageName }.distinct()
    }

    /** 从 getPackageInfo 返回的组件数组采集四大组件（公开 API）。 */
    private fun collectComponents(info: PackageInfo): List<ComponentInfo> {
        val out = mutableListOf<ComponentInfo>()
        @Suppress("DEPRECATION")
        info.activities?.forEach {
            out.add(ComponentInfo(it.name ?: "?", ComponentType.ACTIVITY, it.exported, it.permission))
        }
        @Suppress("DEPRECATION")
        info.services?.forEach {
            out.add(ComponentInfo(it.name ?: "?", ComponentType.SERVICE, it.exported, it.permission))
        }
        @Suppress("DEPRECATION")
        info.receivers?.forEach {
            out.add(ComponentInfo(it.name ?: "?", ComponentType.RECEIVER, it.exported, it.permission))
        }
        @Suppress("DEPRECATION")
        info.providers?.forEach {
            out.add(ComponentInfo(it.name ?: "?", ComponentType.PROVIDER, it.exported, it.readPermission ?: it.writePermission))
        }
        return out
    }

    /** 在 APK 内的 classes*.dex 原始字节中探测特征串（不依赖第三方 Dex 解析库）。 */
    private fun scanDex(apkPath: String?, probes: Set<String>): Set<String> {
        if (apkPath == null || probes.isEmpty()) return emptySet()
        val hits = mutableSetOf<String>()
        try {
            ZipFile(File(apkPath)).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    if (!e.name.startsWith("classes") || !e.name.endsWith(".dex")) continue
                    if (e.size > 32L * 1024 * 1024) continue
                    val bytes = zip.getInputStream(e).readBytes()
                    for (p in probes) {
                        if (hits.contains(p)) continue
                        if (containsAscii(bytes, p)) hits.add(p)
                    }
                }
            }
        } catch (_: Exception) {
        }
        return hits
    }

    private fun containsAscii(bytes: ByteArray, s: String): Boolean {
        val needle = s.toByteArray(Charsets.US_ASCII)
        if (needle.isEmpty() || needle.size > bytes.size) return false
        outer@ for (i in 0..bytes.size - needle.size) {
            for (j in needle.indices) {
                if (bytes[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    private fun signatureHash(info: PackageInfo, pkg: String): String {
        return try {
            @Suppress("DEPRECATION")
            val sigs = if (Build.VERSION.SDK_INT >= 28 && info.signingInfo != null) {
                info.signingInfo.apkContentsSigners
            } else {
                info.signatures
            }
            if (sigs.isNullOrEmpty()) "sig-missing-$pkg"
            else sha256Hex(sigs[0].toByteArray())
        } catch (_: Exception) {
            "sig-error-$pkg"
        }
    }

    private fun isUnknownSource(pkg: String): Boolean {
        val pm = context.packageManager
        val stores = setOf(
            "com.android.vending", "com.google.android.packageinstaller",
            "com.android.packageinstaller", "com.huawei.appmarket",
            "com.xiaomi.market", "com.bbk.appstore", "com.oplus.appdetail",
        )
        return try {
            val installer = if (Build.VERSION.SDK_INT >= 30) {
                pm.getInstallSourceInfo(pkg).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(pkg)
            }
            installer == null || !stores.any { installer.startsWith(it) }
        } catch (_: Exception) {
            false
        }
    }

    private fun sha256OfFile(f: File): String? {
        return try {
            if (!f.isFile) return null
            val md = MessageDigest.getInstance("SHA-256")
            f.inputStream().use { input ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    md.update(buf, 0, n)
                }
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            null
        }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
