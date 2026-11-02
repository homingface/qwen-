package com.shieldpatrol.engine

/** 规则条件：单个条件 + 多条件 AND。 */
sealed class Condition {
    abstract fun matches(f: AppFeatures): Boolean
    abstract fun describe(): String
}

class PermAll(val perms: Set<String>) : Condition() {
    override fun matches(f: AppFeatures) = f.permissions.containsAll(perms)
    override fun describe() = "permAll=${perms.joinToString("|")}"
}

class PermAny(val perms: Set<String>) : Condition() {
    override fun matches(f: AppFeatures) = f.permissions.any { it in perms }
    override fun describe() = "permAny=${perms.joinToString("|")}"
}

class DexAny(val needles: Set<String>) : Condition() {
    override fun matches(f: AppFeatures) =
        f.dexStrings.any { d -> needles.any { d.contains(it, ignoreCase = true) } }
    override fun describe() = "dexAny=${needles.joinToString("|")}"
}

/** compAny=TYPE:permissionContains，如 SERVICE:accessibility */
class CompAny(private val type: ComponentType?, private val permContains: String) : Condition() {
    override fun matches(f: AppFeatures) = f.components.any { c ->
        (type == null || c.type == type) &&
                (c.permission?.contains(permContains, ignoreCase = true) == true ||
                        c.name.contains(permContains, ignoreCase = true))
    }
    override fun describe() = "compAny=${type?.name ?: "ANY"}:$permContains"
}

class FlagDynamic : Condition() {
    override fun matches(f: AppFeatures) = f.usesDynamicCodeLoading
    override fun describe() = "flag=dynamic"
}

class FlagDebug : Condition() {
    override fun matches(f: AppFeatures) = f.debuggable
    override fun describe() = "flag=debug"
}

class FlagUnknown : Condition() {
    override fun matches(f: AppFeatures) = f.installedFromUnknownSource
    override fun describe() = "flag=unknown"
}

class MaxTargetSdk(private val n: Int) : Condition() {
    override fun matches(f: AppFeatures) = f.targetSdk <= n
    override fun describe() = "maxTargetSdk=$n"
}

class Rule(
    val id: String,
    val category: ThreatCategory,
    val weight: Int,
    val conditions: List<Condition>,
    val note: String = "",
) {
    /** 全部条件 AND 满足才命中。无条件规则永不命中。 */
    fun match(f: AppFeatures): Finding? {
        if (conditions.isEmpty()) return null
        if (!conditions.all { it.matches(f) }) return null
        return Finding(
            ruleId = id,
            detail = note.ifEmpty { conditions.joinToString(" 且 ") { it.describe() } },
            weight = weight,
            category = category,
        )
    }

    /** 供采集器预筛：该规则需要探测的 Dex 特征串。 */
    fun dexProbes(): Set<String> = conditions.filterIsInstance<DexAny>().flatMap { it.needles }.toSet()
}
