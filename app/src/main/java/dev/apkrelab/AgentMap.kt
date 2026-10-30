package dev.apkrelab

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.DashPathEffect
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.view.MotionEvent
import android.view.View
import android.view.ViewConfiguration

/**
 * 0.37.1: live org chart of the AI Hub. 0.37.2: redesigned to fit the screen WIDTH (no horizontal scroll):
 * the Lead AI on top, a centre spine, and tool-group cards in two columns (each group is a card, each tool a row).
 * While the agent runs: the tool being executed pulses, tools used in this request get a check mark, tools that ask
 * the user first have a dashed border and an "asks" tag. Tapping a row does the same as the Tools palette.
 */
class AgentMapView(context: Context) : View(context) {

    private class Leaf(val key: String, val label: String, val asks: Boolean, val spec: ToolSpec?) {
        val rect = RectF()
    }

    private class Group(val name: String, val color: Int, val leaves: List<Leaf>) {
        val card = RectF()
        val head = RectF()
        var left = true
    }

    companion object {
        private val groupColors = intArrayOf(
            0xFF1E88E5.toInt(), 0xFFFB8C00.toInt(), 0xFF7E57C2.toInt(), 0xFFD81B60.toInt(),
            0xFF43A047.toInt(), 0xFF546E7A.toInt(), 0xFF00897B.toInt()
        )

        /** Colour of a tool group ("Inspect", "Security", ..., "Team"); same colours as the Map tab. */
        fun colorFor(group: String): Int {
            val i = (Tools.groups + "Team").indexOf(group)
            return groupColors[(if (i < 0) 5 else i) % groupColors.size]
        }

        /** Tool name -> display label and colour, or null when [key] is not a tool. */
        fun labelFor(key: String): String? = when (key) {
            "delegate" -> "Delegate"
            "delegate_many" -> "Delegate (many)"
            else -> Tools.all.firstOrNull { it.name == key }?.label
        }

        fun colorForTool(key: String): Int =
            colorFor(Tools.all.firstOrNull { it.name == key }?.group ?: "Team")
    }

    private val groups: List<Group>
    private val leafByKey = HashMap<String, Leaf>()

    var onPick: ((ToolSpec) -> Unit)? = null
    /** Centre (px) of the row that just became active, so the host can scroll to it. */
    var onFocus: ((Int, Int) -> Unit)? = null
    /** Called whenever the live state changes (for the status strip). */
    var onState: (() -> Unit)? = null

    private var active: String? = null
    private var running = false
    private var leadText = ""
    private val used = LinkedHashMap<String, Int>()
    private var pulse = 0f
    private val rr = RectF()
    private val leadRect = RectF()
    private var spineX = 0f
    private var spineEnd = 0f

    private val fill = Paint(Paint.ANTI_ALIAS_FLAG)
    private val line = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.STROKE }
    private val txt = Paint(Paint.ANTI_ALIAS_FLAG)
    private val slop = ViewConfiguration.get(context).scaledTouchSlop
    private var downX = 0f
    private var downY = 0f

    private val margin = Ui.dp(12)
    private val spineGap = Ui.dp(22)
    private val leafH = Ui.dp(32)
    private val leafGap = Ui.dp(6)
    private val headH = Ui.dp(36)
    private val inPad = Ui.dp(8)
    private val leadH = Ui.dp(60)

    private val animator = ValueAnimator.ofFloat(0f, 1f).apply {
        duration = 800
        repeatCount = ValueAnimator.INFINITE
        repeatMode = ValueAnimator.REVERSE
        addUpdateListener { pulse = it.animatedValue as Float; invalidate() }
    }

    init {
        val names = Tools.groups + "Team"
        val list = ArrayList<Group>()
        for ((gi, g) in names.withIndex()) {
            val leaves = ArrayList<Leaf>()
            if (g == "Team") {
                leaves.add(Leaf("delegate", "Delegate to a worker", false, null))
                leaves.add(Leaf("delegate_many", "Delegate to 5 workers", false, null))
            } else {
                for (t in Tools.all) if (t.group == g) leaves.add(Leaf(t.name, t.label, t.asks, t))
            }
            for (l in leaves) leafByKey[l.key] = l
            list.add(Group(g, groupColors[gi % groupColors.size], leaves))
        }
        groups = list
    }

    // ---------- state (UI thread) ----------

    fun reset() { active = null; used.clear(); leadText = ""; invalidate(); onState?.invoke() }

    fun setRunning(on: Boolean) {
        running = on
        if (on) { if (!animator.isStarted) animator.start() }
        else { animator.cancel(); pulse = 0f; active = null }
        invalidate()
        onState?.invoke()
    }

    fun setLead(s: String) { leadText = s; invalidate(); onState?.invoke() }

    fun isRunning(): Boolean = running
    fun stepCount(): Int = used.values.sum()
    fun activeLabel(): String? = active?.let { k -> leafByKey[k]?.label }

    /** Fed with every line the agent reports. A line starting with a tool name starts that tool; worker / council progress keeps it lit. */
    fun onStep(s: String) {
        val first = s.trim().substringBefore(' ').substringBefore('{')
        if (leafByKey.containsKey(first)) {
            active = first
            used[first] = (used[first] ?: 0) + 1
            leafByKey[first]?.let { l -> if (l.rect.width() > 0f) onFocus?.invoke(l.rect.centerX().toInt(), l.rect.centerY().toInt()) }
        } else if (s.startsWith("\u2696") && leafByKey.containsKey("propose_edit")) {
            active = "propose_edit"
        }
        invalidate()
        onState?.invoke()
    }

    // ---------- layout: two masonry columns under a centre spine ----------

    override fun onMeasure(widthSpec: Int, heightSpec: Int) {
        var w = MeasureSpec.getSize(widthSpec)
        if (w <= 0) w = Ui.dp(360)
        val cardW = (w - 2 * margin - spineGap) / 2f
        val leftX = margin.toFloat()
        val rightX = leftX + cardW + spineGap

        val leadW = minOf(w - 2 * margin, Ui.dp(300)).toFloat()
        leadRect.set((w - leadW) / 2f, Ui.dp(10).toFloat(), (w + leadW) / 2f, (Ui.dp(10) + leadH).toFloat())
        spineX = w / 2f

        val top = leadRect.bottom + Ui.dp(26)
        var yL = top
        var yR = top
        var lastStub = top
        for (g in groups) {
            val h = headH + inPad + g.leaves.size * (leafH + leafGap) + inPad - leafGap
            val left = yL <= yR
            g.left = left
            val x = if (left) leftX else rightX
            val y = if (left) yL else yR
            g.card.set(x, y, x + cardW, y + h)
            g.head.set(x, y, x + cardW, y + headH)
            for ((k, lf) in g.leaves.withIndex()) {
                val ly = y + headH + inPad + k * (leafH + leafGap)
                lf.rect.set(x + inPad, ly, x + cardW - inPad, ly + leafH)
            }
            if (left) yL = y + h + Ui.dp(14) else yR = y + h + Ui.dp(14)
            lastStub = maxOf(lastStub, g.head.centerY())
        }
        spineEnd = lastStub
        setMeasuredDimension(w, (maxOf(yL, yR) + Ui.dp(10)).toInt())
    }

    // ---------- drawing ----------

    private fun fit(s: String, paint: Paint, maxW: Float): String {
        if (paint.measureText(s) <= maxW) return s
        val n = paint.breakText(s, true, maxW - paint.measureText("..."), null)
        return s.take(maxOf(0, n)) + "..."
    }

    private fun withAlpha(c: Int, a: Int): Int = Color.argb(a.coerceIn(0, 255), Color.red(c), Color.green(c), Color.blue(c))

    override fun onDraw(canvas: Canvas) {
        val ink = Ui.p.ink
        val r = Ui.dp(10).toFloat()

        // spine + stubs
        line.color = Ui.p.stroke
        line.strokeWidth = Ui.dp(2).toFloat()
        line.pathEffect = null
        canvas.drawLine(spineX, leadRect.bottom, spineX, spineEnd, line)
        for (g in groups) {
            val y = g.head.centerY()
            if (g.left) canvas.drawLine(g.card.right, y, spineX, y, line) else canvas.drawLine(spineX, y, g.card.left, y, line)
        }

        // lead node
        val thinking = running && active == null
        fill.style = Paint.Style.FILL
        fill.color = Ui.p.primary
        canvas.drawRoundRect(leadRect, r * 1.4f, r * 1.4f, fill)
        if (thinking) {
            line.color = withAlpha(Ui.p.accent, (90 + 165 * pulse).toInt())
            line.strokeWidth = Ui.dp(3).toFloat()
            canvas.drawRoundRect(leadRect, r * 1.4f, r * 1.4f, line)
        }
        txt.textAlign = Paint.Align.CENTER
        txt.typeface = Typeface.DEFAULT_BOLD
        txt.textSize = Ui.dp(16).toFloat()
        txt.color = Color.WHITE
        canvas.drawText("Lead AI", leadRect.centerX(), leadRect.centerY() - Ui.dp(5), txt)
        txt.typeface = Typeface.DEFAULT
        txt.textSize = Ui.dp(11).toFloat()
        txt.color = withAlpha(Color.WHITE, 210)
        val leadSub = if (!running) "idle - ask me anything" else if (leadText.isNotEmpty()) leadText else "working"
        canvas.drawText(fit(leadSub, txt, leadRect.width() - Ui.dp(20)), leadRect.centerX(), leadRect.centerY() + Ui.dp(14), txt)

        // group cards
        for (g in groups) {
            val hasActive = active != null && g.leaves.any { it.key == active }
            rr.set(g.card.left, g.card.top + headH / 2f, g.card.right, g.card.bottom)
            fill.color = Ui.p.surface
            canvas.drawRoundRect(rr, r, r, fill)
            line.color = withAlpha(g.color, if (hasActive) (120 + 135 * pulse).toInt() else 90)
            line.strokeWidth = Ui.dp(if (hasActive) 2 else 1).toFloat()
            canvas.drawRoundRect(rr, r, r, line)
            fill.color = g.color
            canvas.drawRoundRect(g.head, r, r, fill)

            txt.textAlign = Paint.Align.LEFT
            txt.typeface = Typeface.DEFAULT_BOLD
            txt.textSize = Ui.dp(14).toFloat()
            txt.color = Color.WHITE
            canvas.drawText(fit(g.name, txt, g.head.width() - Ui.dp(52)), g.head.left + Ui.dp(12), g.head.centerY() + Ui.dp(5), txt)
            txt.textAlign = Paint.Align.RIGHT
            txt.textSize = Ui.dp(12).toFloat()
            txt.color = withAlpha(Color.WHITE, 200)
            val usedHere = g.leaves.count { (used[it.key] ?: 0) > 0 }
            canvas.drawText(if (usedHere > 0) "$usedHere/${g.leaves.size}" else "${g.leaves.size}", g.head.right - Ui.dp(12), g.head.centerY() + Ui.dp(4), txt)

            for (lf in g.leaves) {
                val isActive = lf.key == active
                val n = used[lf.key] ?: 0
                fill.color = when {
                    isActive -> withAlpha(g.color, (175 + 80 * pulse).toInt())
                    n > 0 -> withAlpha(g.color, 38)
                    else -> Ui.alpha(Ui.p.ink, 0x12)
                }
                canvas.drawRoundRect(lf.rect, r * 0.8f, r * 0.8f, fill)
                line.color = if (isActive) g.color else withAlpha(g.color, 110)
                line.strokeWidth = Ui.dp(if (isActive) 2 else 1).toFloat()
                line.pathEffect = if (lf.asks) DashPathEffect(floatArrayOf(Ui.dp(4).toFloat(), Ui.dp(3).toFloat()), 0f) else null
                canvas.drawRoundRect(lf.rect, r * 0.8f, r * 0.8f, line)
                line.pathEffect = null

                // right badge first so the label can leave room for it
                var reserve = Ui.dp(10).toFloat()
                txt.textAlign = Paint.Align.RIGHT
                txt.typeface = Typeface.DEFAULT_BOLD
                if (n > 0) {
                    txt.textSize = Ui.dp(13).toFloat()
                    txt.color = if (isActive) Color.WHITE else g.color
                    val tag = if (n > 1) "\u2713$n" else "\u2713"
                    canvas.drawText(tag, lf.rect.right - Ui.dp(9), lf.rect.centerY() + Ui.dp(5), txt)
                    reserve += txt.measureText(tag) + Ui.dp(6)
                } else if (lf.asks) {
                    txt.textSize = Ui.dp(10).toFloat()
                    txt.typeface = Typeface.DEFAULT
                    txt.color = Ui.p.sub
                    canvas.drawText("asks", lf.rect.right - Ui.dp(9), lf.rect.centerY() + Ui.dp(4), txt)
                    reserve += txt.measureText("asks") + Ui.dp(6)
                }
                txt.textAlign = Paint.Align.LEFT
                txt.typeface = if (isActive) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
                txt.textSize = Ui.dp(13).toFloat()
                txt.color = if (isActive) Color.WHITE else ink
                canvas.drawText(fit(lf.label, txt, lf.rect.width() - reserve - Ui.dp(10)), lf.rect.left + Ui.dp(10), lf.rect.centerY() + Ui.dp(5), txt)
            }
        }
        txt.typeface = Typeface.DEFAULT
        txt.textAlign = Paint.Align.LEFT
    }

    // ---------- touch: tap a row = same as the Tools palette ----------

    override fun onTouchEvent(e: MotionEvent): Boolean {
        when (e.actionMasked) {
            MotionEvent.ACTION_DOWN -> { downX = e.x; downY = e.y; return true }
            MotionEvent.ACTION_UP -> {
                if (Math.abs(e.x - downX) < slop && Math.abs(e.y - downY) < slop) {
                    for (g in groups) for (lf in g.leaves) {
                        if (lf.rect.contains(e.x, e.y)) {
                            val sp = lf.spec
                            if (sp != null) onPick?.invoke(sp)
                            return true
                        }
                    }
                }
            }
        }
        return super.onTouchEvent(e)
    }

    override fun onDetachedFromWindow() {
        animator.cancel()
        super.onDetachedFromWindow()
    }
}
