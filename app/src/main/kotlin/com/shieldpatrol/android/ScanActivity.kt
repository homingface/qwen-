package com.shieldpatrol.android

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.shieldpatrol.engine.Verdict
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/** 扫描结果列表页：按风险分数排序展示所有已扫描应用。 */
class ScanActivity : AppCompatActivity() {

    private val adapter = ResultAdapter()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan)
        val rv = findViewById<RecyclerView>(R.id.rvResults)
        rv.layoutManager = LinearLayoutManager(this)
        rv.adapter = adapter

        rv.addOnItemTouchListener(
            SimpleClickTouch(rv) { pos ->
                val item = adapter.items.getOrNull(pos) ?: return@SimpleClickTouch
                val intent = Intent(this, AppDetailActivity::class.java)
                intent.putExtra(AppDetailActivity.EXTRA_PKG, item.features.packageName)
                startActivity(intent)
            }
        )

        val status = findViewById<TextView>(R.id.tvScanStatus)
        val bar = findViewById<ProgressBar>(R.id.pbScan)
        lifecycleScope.launch {
            ScanState.progress.collectLatest { p ->
                status.text = if (p.running) getString(R.string.scanning) + " ${p.done}/${p.total}"
                else "扫描完成：共 ${p.total} 个应用"
                bar.max = if (p.total > 0) p.total else 1
                bar.progress = p.done
            }
        }
        lifecycleScope.launch {
            ScanState.items.collectLatest { adapter.submit(it) }
        }
    }

    private class ResultAdapter : RecyclerView.Adapter<ResultAdapter.VH>() {
        var items: List<ScanState.Item> = emptyList()
            private set

        fun submit(list: List<ScanState.Item>) {
            items = list
            notifyDataSetChanged()
        }

        class VH(v: View) : RecyclerView.ViewHolder(v) {
            val label: TextView = v.findViewById(R.id.tvLabel)
            val pkg: TextView = v.findViewById(R.id.tvPackage)
            val verdict: TextView = v.findViewById(R.id.tvVerdict)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH =
            VH(LayoutInflater.from(parent.context).inflate(R.layout.item_app, parent, false))

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]
            holder.label.text = item.features.label
            holder.pkg.text = item.features.packageName
            val ctx = holder.itemView.context
            val (text, color) = when (item.result.verdict) {
                Verdict.MALICIOUS -> "恶意（${item.result.category?.label ?: "通用"} · ${item.result.score}分）" to ctx.getColor(R.color.verdict_malicious)
                Verdict.SUSPICIOUS -> "可疑（${item.result.category?.label ?: "通用"} · ${item.result.score}分）" to ctx.getColor(R.color.verdict_suspicious)
                Verdict.SAFE -> "安全" to ctx.getColor(R.color.verdict_safe)
            }
            holder.verdict.text = text
            holder.verdict.setTextColor(color)
        }

        override fun getItemCount(): Int = items.size
    }
}

/** RecyclerView 行点击（避免依赖 ItemClick 库）。 */
class SimpleClickTouch(
    private val rv: RecyclerView,
    private val onClick: (Int) -> Unit,
) : RecyclerView.OnItemTouchListener {

    private val gestureDetector = android.view.GestureDetector(
        rv.context,
        object : android.view.GestureDetector.SimpleOnGestureListener() {
            override fun onSingleTapUp(e: android.view.MotionEvent): Boolean {
                val child = rv.findChildViewUnder(e.x, e.y) ?: return false
                val pos = rv.getChildAdapterPosition(child)
                if (pos != RecyclerView.NO_POSITION) onClick(pos)
                return true
            }
        })

    override fun onInterceptTouchEvent(rv: RecyclerView, e: android.view.MotionEvent): Boolean {
        gestureDetector.onTouchEvent(e)
        return false
    }

    override fun onTouchEvent(rv: RecyclerView, e: android.view.MotionEvent) {}
    override fun onRequestDisallowInterceptTouchEvent(disallowIntercept: Boolean) {}
}
