package com.shieldpatrol.engine

/**
 * 自定义规则文本格式：每行 ID;类别;权重;条件1[;条件2...][;note=说明]
 * 支持条件：permAll=a|b / permAny=a|b / dexAny=a|b / compAny=SERVICE:sms /
 * flag=dynamic|debug|unknown / maxTargetSdk=n
 */
object CustomRuleFormat {

    fun parse(text: String): List<Rule> =
        text.lineSequence().map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull { parseLine(it) }
            .toList()

    fun export(rules: List<Rule>): String =
        rules.joinToString("\n") { rule ->
            val parts = buildList {
                add(rule.id)
                add(rule.category.name)
                add(rule.weight.toString())
                rule.conditions.forEach { add(it.describe()) }
                if (rule.note.isNotEmpty()) add("note=${rule.note}")
            }
            parts.joinToString(";")
        }

    private fun parseLine(line: String): Rule? {
        val parts = line.split(";").map { it.trim() }
        if (parts.size < 4) return null
        val id = parts[0].ifEmpty { return null }
        val category = ThreatCategory.fromName(parts[1]) ?: return null
        val weight = parts[2].toIntOrNull()?.coerceIn(0, 100) ?: return null
        val conditions = mutableListOf<Condition>()
        var note = ""
        for (raw in parts.drop(3)) {
            val cond = parseCondition(raw)
            if (cond != null) conditions.add(cond)
            else if (raw.startsWith("note=")) note = raw.removePrefix("note=")
            // 无法识别的条件段整行作废，避免半条规则生效
            else return null
        }
        if (conditions.isEmpty()) return null
        return Rule(id, category, weight, conditions, note)
    }

    private fun parseCondition(s: String): Condition? {
        val eq = s.indexOf('=')
        if (eq <= 0) return null
        val key = s.substring(0, eq).lowercase()
        val value = s.substring(eq + 1)
        if (value.isEmpty()) return null
        return when (key) {
            "permall" -> PermAll(value.split("|").map { it.trim() }.filter { it.isNotEmpty() }.toSet())
            "permany" -> PermAny(value.split("|").map { it.trim() }.filter { it.isNotEmpty() }.toSet())
            "dexany" -> DexAny(value.split("|").map { it.trim() }.filter { it.isNotEmpty() }.toSet())
            "company" -> {
                val idx = value.indexOf(':')
                if (idx < 0) return null
                val typeName = value.substring(0, idx).uppercase()
                val rest = value.substring(idx + 1)
                if (rest.isEmpty()) return null
                val type = ComponentType.entries.firstOrNull { it.name == typeName }
                CompAny(type, rest)
            }
            "flag" -> when (value.lowercase()) {
                "dynamic" -> FlagDynamic()
                "debug" -> FlagDebug()
                "unknown" -> FlagUnknown()
                else -> null
            }
            "maxtargetsdk" -> value.toIntOrNull()?.let { MaxTargetSdk(it) }
            else -> null
        }
    }
}
