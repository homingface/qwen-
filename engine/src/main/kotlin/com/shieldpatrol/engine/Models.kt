package com.shieldpatrol.engine

/** 组件类型 */
enum class ComponentType { ACTIVITY, SERVICE, RECEIVER, PROVIDER }

data class ComponentInfo(
    val name: String,
    val type: ComponentType,
    val exported: Boolean,
    val permission: String?,
)

/** 检测判定 */
enum class Verdict { SAFE, SUSPICIOUS, MALICIOUS }

/** 恶意类别 */
enum class ThreatCategory(val label: String) {
    TROJAN("木马"),
    RANSOMWARE("勒索"),
    ADWARE("广告劫持"),
    PRIVACY_STEALER("隐私窃取"),
    MINER("挖矿"),
    BACKDOOR("后门"),
    GENERIC("通用");

    companion object {
        fun fromName(s: String): ThreatCategory? =
            entries.firstOrNull { it.name.equals(s, ignoreCase = true) }
    }
}

/** 单个应用交给引擎的全部特征。 */
data class AppFeatures(
    val packageName: String,
    val label: String,
    val sha256: String?,
    val signatureHash: String?,
    val permissions: Set<String>,
    val components: List<ComponentInfo>,
    val dexStrings: Set<String>,
    val usesDynamicCodeLoading: Boolean,
    val debuggable: Boolean,
    val installedFromUnknownSource: Boolean,
    val targetSdk: Int,
)

data class Finding(
    val ruleId: String,
    val detail: String,
    val weight: Int,
    val category: ThreatCategory = ThreatCategory.GENERIC,
)

enum class ListKind { WHITE, BLACK }

data class ListEntry(val kind: ListKind, val packageName: String, val note: String)

data class DetectionResult(
    val verdict: Verdict,
    val score: Int,
    val category: ThreatCategory?,
    val findings: List<Finding>,
    val whitelistHit: Boolean = false,
    val blacklistHit: Boolean = false,
)
