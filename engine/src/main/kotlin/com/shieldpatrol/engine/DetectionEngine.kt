package com.shieldpatrol.engine

/** 规则引擎：名单 → 恶意哈希库 → 行为规则打分 → 分级与类别归类。 */
class DetectionEngine(
    private val rules: List<Rule>,
    private val db: MalwareHashDb,
    private val lists: ListManager,
) {

    fun detect(f: AppFeatures): DetectionResult {
        if (lists.isWhitelisted(f.packageName)) {
            return DetectionResult(Verdict.SAFE, 0, null, emptyList(), whitelistHit = true)
        }
        if (lists.isBlacklisted(f.packageName)) {
            return DetectionResult(
                Verdict.MALICIOUS, 100, ThreatCategory.GENERIC,
                listOf(Finding("BLACKLIST", "命中黑名单", 100)),
                blacklistHit = true,
            )
        }
        db.match(f.sha256, f.signatureHash)?.let { hit ->
            return DetectionResult(
                Verdict.MALICIOUS, 100, hit.entry.category,
                listOf(Finding("MALWARE_DB", "命中本地恶意库：${hit.entry.name}", 100, hit.entry.category)),
            )
        }
        val findings = rules.mapNotNull { it.match(f) }
        if (findings.isEmpty()) {
            return DetectionResult(Verdict.SAFE, 0, null, emptyList())
        }
        val score = findings.sumOf { it.weight }.coerceAtMost(100)
        val verdict = when {
            score >= 70 -> Verdict.MALICIOUS
            score >= 40 -> Verdict.SUSPICIOUS
            else -> Verdict.SAFE
        }
        val category = findings.maxByOrNull { it.weight }?.category
        return DetectionResult(verdict, score, category, findings.sortedByDescending { it.weight })
    }

    /** 采集阶段需要探测的全部 Dex 特征串（避免全盘扫描字符串表）。 */
    fun allDexProbes(): Set<String> = rules.flatMap { it.dexProbes() }.toSet()
}
