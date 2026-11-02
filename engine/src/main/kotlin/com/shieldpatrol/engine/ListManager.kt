package com.shieldpatrol.engine

/** 黑/白名单管理。白名单豁免检测；黑名单直接判恶意拦截。支持文本导入导出。 */
class ListManager {

    private val white = linkedMapOf<String, String>()
    private val black = linkedMapOf<String, String>()

    fun addWhite(pkg: String, note: String) { white[pkg] = note }
    fun addBlack(pkg: String, note: String) { black[pkg] = note }
    fun removeWhite(pkg: String) { white.remove(pkg) }
    fun removeBlack(pkg: String) { black.remove(pkg) }

    fun isWhitelisted(pkg: String): Boolean = white.containsKey(pkg)
    fun isBlacklisted(pkg: String): Boolean = black.containsKey(pkg)

    fun entries(kind: ListKind): List<ListEntry> = when (kind) {
        ListKind.WHITE -> white.map { ListEntry(ListKind.WHITE, it.key, it.value) }
        ListKind.BLACK -> black.map { ListEntry(ListKind.BLACK, it.key, it.value) }
    }

    fun export(): String {
        val sb = StringBuilder()
        white.forEach { (pkg, note) -> sb.appendLine("WHITE;$pkg;$note") }
        black.forEach { (pkg, note) -> sb.appendLine("BLACK;$pkg;$note") }
        return sb.toString()
    }

    companion object {
        fun import(text: String): ListManager {
            val m = ListManager()
            text.lineSequence().map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .forEach { line ->
                    val parts = line.split(";")
                    if (parts.size < 2) return@forEach
                    val kind = parts[0].trim().uppercase()
                    val pkg = parts[1].trim()
                    if (pkg.isEmpty()) return@forEach
                    val note = if (parts.size > 2) parts[2].trim() else ""
                    when (kind) {
                        "WHITE" -> m.addWhite(pkg, note)
                        "BLACK" -> m.addBlack(pkg, note)
                    }
                }
            return m
        }
    }
}
