package com.shieldpatrol.android

import com.shieldpatrol.engine.AppFeatures
import com.shieldpatrol.engine.DetectionResult
import com.shieldpatrol.engine.Verdict
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** 扫描进度与结果的全局状态（服务写、界面读）。 */
object ScanState {

    data class Item(val features: AppFeatures, val result: DetectionResult)

    data class Progress(val running: Boolean, val total: Int, val done: Int, val current: String)

    private val _progress = MutableStateFlow(Progress(false, 0, 0, ""))
    val progress: StateFlow<Progress> = _progress

    private val _items = MutableStateFlow<List<Item>>(emptyList())
    val items: StateFlow<List<Item>> = _items

    fun setProgress(running: Boolean, total: Int, done: Int, current: String) {
        _progress.value = Progress(running, total, done, current)
    }

    fun setItems(list: List<Item>) {
        val cmp = compareByDescending<Item> { it.result.score }
            .thenBy { verdictRank(it) }
        _items.value = list.sortedWith(cmp)
    }

    private fun verdictRank(i: Item): Int = when (i.result.verdict) {
        Verdict.MALICIOUS -> 0
        Verdict.SUSPICIOUS -> 1
        else -> 2
    }
}
