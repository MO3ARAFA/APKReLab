package dev.apkrelab

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.PixelFormat
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.Rect
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.AbsoluteSizeSpan
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView

/**
 * 0.37.9: Liquid Glass look (ambient colour field + translucent glass surfaces with a specular rim, floating pill
 * navigation). 0.24.0: look & feel. Two palettes ("midnight" = navy/purple + orange, "ocean" = blue + peach),
 * a hero header over a white rounded sheet, pill buttons, card rows. No XML layouts: the app builds
 * its views in code, so [skin] restyles the existing views instead of touching every call site.
 */
object Ui {

    class Palette(
        val key: String,
        val heroTop: Int, val heroBottom: Int,
        val primary: Int,            // filled buttons (white text)
        val accent: Int,             // highlight: selected tab, main call-to-action
        val onAccent: Int,           // text on accent
        val tint: Int, val tintText: Int,   // soft buttons
        val ink: Int, val sub: Int,  // main / secondary text
        val code: Int, val stroke: Int,
        val surface: Int = 0xFFFFFFFF.toInt(),   // cards, fields, bubbles (white in the light looks)
        val dark: Boolean = false,
        // 0.37.9 Liquid Glass
        val bgTop: Int = 0xFF0A0920.toInt(), val bgBottom: Int = 0xFF1B1450.toInt(),   // ambient field behind everything
        val glow1: Int = 0xFF6A5BE8.toInt(), val glow2: Int = 0xFFFF8A3D.toInt(),      // soft colour glows in the field
        val glass: Int = 0x14FFFFFF,      // large glass panel fill
        val glassHi: Int = 0x24FFFFFF,    // small glass controls (nav pill, chips)
        val rimHi: Int = 0x66FFFFFF,      // specular rim: bright edge ...
        val rimLo: Int = 0x14FFFFFF,      // ... and the faint middle
        val sel: Int = 0x2EFFFFFF,        // selected lens inside the nav pill
        val hi: Int = 0xFFFFB74D.toInt(), // active icon / label colour on glass
        val heroInk: Int = 0xFFFFFFFF.toInt(),   // text drawn straight on the ambient field
        val well: Int = 0x40000000   // inset boxes (code, logs, manifest)
    )

    val midnight = Palette(
        "midnight",
        heroTop = 0xFF1B1464.toInt(), heroBottom = 0xFF4A3BC0.toInt(),
        primary = 0xFF4A3BC0.toInt(), accent = 0xFFFFA726.toInt(), onAccent = 0xFF1B1464.toInt(),
        tint = 0x1A4A3BC0, tintText = 0xFF352A9E.toInt(),
        ink = 0xFF1B1A3A.toInt(), sub = 0xFF66658A.toInt(),
        code = 0xFFF6F5FD.toInt(), stroke = 0x264A3BC0,
        surface = 0xCCFFFFFF.toInt(),
        bgTop = 0xFFF4F2FF.toInt(), bgBottom = 0xFFDCD7F8.toInt(),
        glow1 = 0xFF8E7CFF.toInt(), glow2 = 0xFFFFB74D.toInt(),
        glass = 0x8CFFFFFF.toInt(), glassHi = 0xB8FFFFFF.toInt(),
        rimHi = 0xFFFFFFFF.toInt(), rimLo = 0x334A3BC0,
        sel = 0x244A3BC0, hi = 0xFF4A3BC0.toInt(), heroInk = 0xFF1B1A3A.toInt(),
        well = 0x12000000
    )

    val ocean = Palette(
        "ocean",
        heroTop = 0xFF2B97F0.toInt(), heroBottom = 0xFF1E6FD0.toInt(),
        primary = 0xFF1E78DC.toInt(), accent = 0xFFF9B8A0.toInt(), onAccent = 0xFF14325C.toInt(),
        tint = 0x1A1E78DC, tintText = 0xFF14579F.toInt(),
        ink = 0xFF12263F.toInt(), sub = 0xFF5A6E85.toInt(),
        code = 0xFFF3F8FD.toInt(), stroke = 0x261E78DC,
        surface = 0xCCFFFFFF.toInt(),
        bgTop = 0xFFEAF4FF.toInt(), bgBottom = 0xFFCFE5FA.toInt(),
        glow1 = 0xFF4FA8F5.toInt(), glow2 = 0xFFF9B8A0.toInt(),
        glass = 0x8CFFFFFF.toInt(), glassHi = 0xB8FFFFFF.toInt(),
        rimHi = 0xFFFFFFFF.toInt(), rimLo = 0x331E78DC,
        sel = 0x241E78DC, hi = 0xFF1E78DC.toInt(), heroInk = 0xFF12263F.toInt(),
        well = 0x12000000
    )

    /** 0.37.4: dark look. Same purple/orange identity, navy surfaces, light text. */
    val night = Palette(
        "night",
        heroTop = 0xFF0A0920.toInt(), heroBottom = 0xFF241F66.toInt(),
        primary = 0xFF6A5BE8.toInt(), accent = 0xFFFFA726.toInt(), onAccent = 0xFF1B1464.toInt(),
        tint = 0x1AFFFFFF, tintText = 0xFFE4E0FF.toInt(),
        ink = 0xFFEDECFA.toInt(), sub = 0xFFA9A7CC.toInt(),
        code = 0xFF121129.toInt(), stroke = 0x26FFFFFF,
        surface = 0x12FFFFFF, dark = true,
        bgTop = 0xFF04030D.toInt(), bgBottom = 0xFF0C0828.toInt(),
        glow1 = 0xFF6A5BE8.toInt(), glow2 = 0xFFFF8A3D.toInt(),
        glass = 0x3D000000, glassHi = 0x1FFFFFFF,
        rimHi = 0x55FFFFFF, rimLo = 0x0FFFFFFF,
        sel = 0x2EFFFFFF, hi = 0xFFFFB74D.toInt(), heroInk = 0xFFFFFFFF.toInt()
    )

    var p: Palette = midnight
    private var d = 1f

    private fun themeKey(ctx: Context): String =
        ctx.getSharedPreferences("apkrelab_prefs", Context.MODE_PRIVATE).getString("theme", "midnight") ?: "midnight"

    /** Call before super.onCreate (setTheme) - see MainActivity. */
    fun themeRes(ctx: Context): Int = when (themeKey(ctx)) {
        "ocean" -> R.style.ReLabOcean
        "night" -> R.style.ReLabNight
        else -> R.style.ReLabMidnight
    }

    fun init(ctx: Context) {
        d = ctx.resources.displayMetrics.density
        p = when (themeKey(ctx)) {
            "ocean" -> ocean
            "night" -> night
            else -> midnight
        }
    }

    /** Syntax colours are written for a light background: in the dark look they are blended 45% toward white. */
    fun hl(c: Int): Int {
        if (!p.dark) return c
        val f = 0.45f
        return Color.rgb(
            (Color.red(c) + (255 - Color.red(c)) * f).toInt(),
            (Color.green(c) + (255 - Color.green(c)) * f).toInt(),
            (Color.blue(c) + (255 - Color.blue(c)) * f).toInt()
        )
    }

    /** A faint overlay of alpha [a] (0..255): black on light looks, white on the dark look. */
    fun shade(a: Int): Int = (if (p.dark) 0x00FFFFFF else 0x00000000) or (a shl 24)

    fun dp(v: Int): Int = (v * d + 0.5f).toInt()

    // ---------- drawables ----------

    fun rr(color: Int, radius: Int, stroke: Int = 0, strokeW: Int = 0): GradientDrawable {
        val g = GradientDrawable()
        g.setColor(color)
        g.cornerRadius = dp(radius).toFloat()
        if (strokeW > 0) g.setStroke(dp(strokeW), stroke)
        return g
    }

    /** White sheet with only the top corners rounded. */
    fun sheet(color: Int, radius: Int): GradientDrawable {
        val g = GradientDrawable()
        g.setColor(color)
        val x = dp(radius).toFloat()
        g.cornerRadii = floatArrayOf(x, x, x, x, 0f, 0f, 0f, 0f)
        return g
    }

    fun ripple(bg: Drawable, radius: Int): RippleDrawable =
        RippleDrawable(ColorStateList.valueOf(if (p.dark) 0x33FFFFFF else 0x22000000), bg, rr(Color.WHITE, radius))

    // ---------- Liquid Glass drawables (0.37.9) ----------

    /**
     * A translucent glass surface: tinted fill, a soft sheen on the upper half and a 1 dp specular rim
     * (bright at the top-left and bottom-right edges, faint in between). The radius is clamped to half the
     * shortest side, so a big radius gives a capsule. No real backdrop blur (not available for plain views).
     */
    class GlassDrawable(private val radiusDp: Int, private val fill: Int, private val sheen: Boolean = true, private val rimOn: Boolean = true) : Drawable() {
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val full = RectF()
        private val edge = RectF()
        private var rimShader: Shader? = null
        private var sheenShader: Shader? = null
        private val rimW = maxOf(1f, Ui.dp(1).toFloat())

        override fun onBoundsChange(b: Rect) {
            super.onBoundsChange(b)
            if (b.width() <= 0 || b.height() <= 0) return
            full.set(b.left.toFloat(), b.top.toFloat(), b.right.toFloat(), b.bottom.toFloat())
            edge.set(full.left + rimW / 2f, full.top + rimW / 2f, full.right - rimW / 2f, full.bottom - rimW / 2f)
            val hi = Ui.p.rimHi
            val tail = Ui.alpha(hi, (hi ushr 24) * 55 / 100)
            rimShader = LinearGradient(full.left, full.top, full.right, full.bottom,
                intArrayOf(hi, Ui.p.rimLo, tail), floatArrayOf(0f, 0.5f, 1f), Shader.TileMode.CLAMP)
            val top = if (Ui.p.dark) 0x16FFFFFF else 0x66FFFFFF
            sheenShader = LinearGradient(0f, full.top, 0f, full.top + full.height() * 0.6f,
                top, 0x00FFFFFF, Shader.TileMode.CLAMP)
        }

        override fun draw(c: Canvas) {
            if (full.isEmpty) return
            val r = minOf(Ui.dp(radiusDp).toFloat(), minOf(full.width(), full.height()) / 2f)
            paint.shader = null
            paint.style = Paint.Style.FILL
            paint.color = fill
            c.drawRoundRect(full, r, r, paint)
            if (sheen) {
                paint.color = Color.BLACK
                paint.shader = sheenShader
                c.drawRoundRect(full, r, r, paint)
            }
            if (!rimOn) { paint.shader = null; return }
            paint.color = Color.BLACK
            paint.shader = rimShader
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = rimW
            val re = maxOf(0f, r - rimW / 2f)
            c.drawRoundRect(edge, re, re, paint)
            paint.shader = null
        }

        override fun setAlpha(alpha: Int) { }
        override fun setColorFilter(colorFilter: android.graphics.ColorFilter?) { }
        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
        override fun getOpacity(): Int = PixelFormat.TRANSLUCENT
    }

    /** The colour field behind the whole UI: a vertical gradient plus two large soft glows the glass picks up. */
    class AmbientDrawable : Drawable() {
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        private var base: Shader? = null
        private var g1: Shader? = null
        private var g2: Shader? = null
        private val box = RectF()

        override fun onBoundsChange(b: Rect) {
            super.onBoundsChange(b)
            val w = b.width().toFloat()
            val h = b.height().toFloat()
            if (w <= 0f || h <= 0f) return
            box.set(b.left.toFloat(), b.top.toFloat(), b.right.toFloat(), b.bottom.toFloat())
            val a1 = if (Ui.p.dark) 0x4A else 0x66
            val a2 = if (Ui.p.dark) 0x24 else 0x55
            base = LinearGradient(0f, box.top, 0f, box.bottom, Ui.p.bgTop, Ui.p.bgBottom, Shader.TileMode.CLAMP)
            g1 = RadialGradient(box.left + w * 0.95f, box.top + h * 0.04f, maxOf(w, h) * 0.7f,
                Ui.alpha(Ui.p.glow1, a1), Ui.alpha(Ui.p.glow1, 0), Shader.TileMode.CLAMP)
            g2 = RadialGradient(box.left + w * 0.02f, box.top + h * 0.95f, maxOf(w, h) * 0.6f,
                Ui.alpha(Ui.p.glow2, a2), Ui.alpha(Ui.p.glow2, 0), Shader.TileMode.CLAMP)
        }

        override fun draw(c: Canvas) {
            if (box.isEmpty) return
            paint.style = Paint.Style.FILL
            paint.color = Color.BLACK
            paint.shader = base
            c.drawRect(box, paint)
            paint.shader = g1
            c.drawRect(box, paint)
            paint.shader = g2
            c.drawRect(box, paint)
            paint.shader = null
        }

        override fun setAlpha(alpha: Int) { }
        override fun setColorFilter(colorFilter: android.graphics.ColorFilter?) { }
        @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
        override fun getOpacity(): Int = PixelFormat.OPAQUE
    }

    /** A glass panel / card background (no ripple). */
    fun glassBg(fill: Int, radius: Int): Drawable = GlassDrawable(radius, fill, false, false)

    private fun margins(v: View, m: Int) {
        val lp = v.layoutParams
        if (lp is ViewGroup.MarginLayoutParams) {
            lp.setMargins(m, m, m, m)
            v.layoutParams = lp
        }
    }

    // ---------- buttons / fields ----------

    private fun base(b: Button, bg: Int, fg: Int, r: Int, bold: Boolean) {
        b.isAllCaps = false
        b.setTextColor(fg)
        b.typeface = if (bold) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
        b.background = ripple(GlassDrawable(r, bg, true, false), r)
        b.stateListAnimator = null
        b.minHeight = 0
        b.minimumHeight = dp(40)
        b.minWidth = 0
        b.minimumWidth = 0
        b.setPadding(dp(8), dp(6), dp(8), dp(6))
        margins(b, dp(3))
    }

    fun tonal(b: Button) = base(b, p.tint, p.tintText, 24, false)
    fun primary(b: Button) = base(b, p.primary, Color.WHITE, 24, true)
    fun accent(b: Button) = base(b, p.accent, p.onAccent, 24, true)
    /** Destructive action (0.37.15): red-tinted glass capsule. */
    fun danger(b: Button) = base(b, alpha(0xFFE53935.toInt(), 0x33), if (p.dark) 0xFFFF8A80.toInt() else 0xFFC62828.toInt(), 24, true)
    fun cta(b: Button) {
        if (p.dark) base(b, Color.WHITE, p.heroTop, 30, true) else base(b, p.primary, Color.WHITE, 30, true)
        b.minimumHeight = dp(56)
    }
    /** Small glass capsule on the ambient field (header chips). */
    fun glass(b: Button) = base(b, p.glassHi, p.heroInk, 24, false)

    fun tab(b: Button, selected: Boolean) {
        base(b, if (selected) p.accent else Color.TRANSPARENT, if (selected) p.onAccent else p.sub, 24, selected)
        if (!selected) b.background = ripple(rr(Color.TRANSPARENT, 24), 24)
        b.minimumHeight = 0
        b.setPadding(dp(2), 0, dp(2), 0)
        margins(b, 0)
    }

    fun field(e: EditText) {
        e.background = GlassDrawable(20, p.surface, true, false)
        e.setTextColor(p.ink)
        e.setHintTextColor(p.sub)
        e.setPadding(dp(14), dp(9), dp(14), dp(9))
        margins(e, dp(3))
    }

    /** Restyles every Button (tag "primary" / "accent" picks a filled style, otherwise soft) and EditText below [v]. */
    fun skin(v: View) {
        if (v is Button) {
            when (v.tag) {
                "primary" -> primary(v)
                "accent" -> accent(v)
                "danger" -> danger(v)
                else -> tonal(v)
            }
        } else if (v is EditText) {
            field(v)
        } else if (v is ViewGroup) {
            for (i in 0 until v.childCount) skin(v.getChildAt(i))
        }
    }

    // ---------- bottom menu sheet (0.37.13) ----------

    /**
     * A dark-glass bottom sheet with a list of actions. An item whose action is null is a small section header.
     * Used by the class screen "More" button so the three rows of action buttons collapse into one slim bar.
     */
    fun menuSheet(act: android.app.Activity, title: String, items: List<Pair<String, (() -> Unit)?>>) {
        val box = LinearLayout(act)
        box.orientation = LinearLayout.VERTICAL
        box.setPadding(dp(12), dp(14), dp(12), dp(10))
        box.background = GlassDrawable(28, if (p.dark) 0xF011102A.toInt() else 0xF5FFFFFF.toInt(), true, true)
        val scroll = android.widget.ScrollView(act)
        scroll.isVerticalScrollBarEnabled = false
        scroll.addView(box)
        // outer margin so the sheet floats clear of the screen edges and the system bars
        val holder = FrameLayout(act)
        holder.setPadding(dp(10), 0, dp(10), dp(12))
        holder.addView(scroll, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        val dlg = android.app.AlertDialog.Builder(act).setView(holder).create()
        val t = TextView(act)
        t.text = title
        t.textSize = 16f
        t.typeface = Typeface.DEFAULT_BOLD
        t.setTextColor(p.ink)
        t.setPadding(dp(10), dp(2), dp(10), dp(8))
        box.addView(t, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        for (item in items) {
            val run = item.second
            if (run == null) {
                val h = TextView(act)
                h.text = item.first.uppercase()
                h.textSize = 10.5f
                h.typeface = Typeface.DEFAULT_BOLD
                h.letterSpacing = 0.08f
                h.setTextColor(p.sub)
                h.setPadding(dp(10), dp(10), dp(10), dp(4))
                box.addView(h, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            } else {
                val b = Button(act)
                b.text = item.first
                tonal(b)
                b.textSize = 14f
                b.gravity = Gravity.CENTER_VERTICAL or Gravity.START
                b.setPadding(dp(16), dp(6), dp(16), dp(6))
                b.setOnClickListener { dlg.dismiss(); run() }
                box.addView(b, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            }
        }
        dlg.show()
        val w = dlg.window
        if (w != null) {
            w.setBackgroundDrawable(android.graphics.drawable.ColorDrawable(0))
            w.setGravity(Gravity.BOTTOM)
            w.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        }
    }

    // ---------- list rows ----------

    val sevRe = rx("^\\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\\]")

    fun sevColor(s: String): Int = when (s) {
        "CRITICAL" -> 0xFFC62828.toInt()
        "HIGH" -> 0xFFEF6C00.toInt()
        "MEDIUM" -> 0xFFF9A825.toInt()
        "LOW" -> 0xFF1E88E5.toInt()
        else -> 0xFF90A4AE.toInt()
    }

    fun alpha(c: Int, a: Int): Int = (c and 0x00FFFFFF) or (a shl 24)

    /** Small vector icons drawn with Canvas (folder, doc, code, shield, cube, up) on an optional round background. */
    class IconView(ctx: Context) : View(ctx) {
        private var kind = "folder"
        private var fg = Color.BLACK
        private var bg = 0
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        /** Glyph size as a fraction of the shorter side. */
        var scale = 0.58f

        fun setup(kind: String, fg: Int, bg: Int) {
            this.kind = kind
            this.fg = fg
            this.bg = bg
            invalidate()
        }

        override fun onDraw(c: Canvas) {
            val w = width.toFloat()
            val h = height.toFloat()
            if (w <= 0f || h <= 0f) return
            if (bg != 0) {
                paint.style = Paint.Style.FILL
                paint.color = bg
                c.drawRoundRect(RectF(0f, 0f, w, h), h / 2f, h / 2f, paint)
            }
            val s = minOf(w, h) * scale
            val cx = w / 2f
            val cy = h / 2f
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = s * 0.11f
            paint.strokeCap = Paint.Cap.ROUND
            paint.strokeJoin = Paint.Join.ROUND
            paint.color = fg
            val path = Path()
            when (kind) {
                "folder" -> {
                    val l = cx - s * 0.5f
                    val r = cx + s * 0.5f
                    val t = cy - s * 0.38f
                    val bt = cy + s * 0.38f
                    path.moveTo(l, t + s * 0.16f)
                    path.lineTo(l, t)
                    path.lineTo(l + s * 0.38f, t)
                    path.lineTo(l + s * 0.52f, t + s * 0.16f)
                    c.drawPath(path, paint)
                    c.drawRoundRect(RectF(l, t + s * 0.16f, r, bt), s * 0.1f, s * 0.1f, paint)
                }
                "doc" -> {
                    c.drawRoundRect(RectF(cx - s * 0.36f, cy - s * 0.5f, cx + s * 0.36f, cy + s * 0.5f), s * 0.1f, s * 0.1f, paint)
                    for (i in 0 until 3) {
                        val y = cy - s * 0.17f + i * s * 0.2f
                        c.drawLine(cx - s * 0.18f, y, cx + s * 0.18f, y, paint)
                    }
                }
                "code" -> {
                    path.moveTo(cx - s * 0.16f, cy - s * 0.3f)
                    path.lineTo(cx - s * 0.46f, cy)
                    path.lineTo(cx - s * 0.16f, cy + s * 0.3f)
                    path.moveTo(cx + s * 0.16f, cy - s * 0.3f)
                    path.lineTo(cx + s * 0.46f, cy)
                    path.lineTo(cx + s * 0.16f, cy + s * 0.3f)
                    c.drawPath(path, paint)
                    c.drawLine(cx + s * 0.08f, cy - s * 0.36f, cx - s * 0.08f, cy + s * 0.36f, paint)
                }
                "shield" -> {
                    val hw = s * 0.42f
                    val hh = s * 0.52f
                    path.moveTo(cx, cy - hh)
                    path.lineTo(cx + hw, cy - hh * 0.62f)
                    path.lineTo(cx + hw, cy)
                    path.quadTo(cx + hw, cy + hh * 0.7f, cx, cy + hh)
                    path.quadTo(cx - hw, cy + hh * 0.7f, cx - hw, cy)
                    path.lineTo(cx - hw, cy - hh * 0.62f)
                    path.close()
                    c.drawPath(path, paint)
                    val chk = Path()
                    chk.moveTo(cx - s * 0.17f, cy)
                    chk.lineTo(cx - s * 0.04f, cy + s * 0.13f)
                    chk.lineTo(cx + s * 0.19f, cy - s * 0.13f)
                    c.drawPath(chk, paint)
                }
                "cube" -> {
                    val dx = s * 0.44f
                    val dy = s * 0.25f
                    path.moveTo(cx, cy - s * 0.5f)
                    path.lineTo(cx + dx, cy - dy)
                    path.lineTo(cx + dx, cy + dy)
                    path.lineTo(cx, cy + s * 0.5f)
                    path.lineTo(cx - dx, cy + dy)
                    path.lineTo(cx - dx, cy - dy)
                    path.close()
                    c.drawPath(path, paint)
                    val inner = Path()
                    inner.moveTo(cx - dx, cy - dy)
                    inner.lineTo(cx, cy)
                    inner.lineTo(cx + dx, cy - dy)
                    inner.moveTo(cx, cy)
                    inner.lineTo(cx, cy + s * 0.5f)
                    c.drawPath(inner, paint)
                }
                "spark" -> {
                    val q = s * 0.5f
                    path.moveTo(cx, cy - q)
                    path.quadTo(cx, cy, cx + q, cy)
                    path.quadTo(cx, cy, cx, cy + q)
                    path.quadTo(cx, cy, cx - q, cy)
                    path.quadTo(cx, cy, cx, cy - q)
                    path.close()
                    c.drawPath(path, paint)
                }
                "chev" -> {
                    path.moveTo(cx - s * 0.12f, cy - s * 0.28f)
                    path.lineTo(cx + s * 0.16f, cy)
                    path.lineTo(cx - s * 0.12f, cy + s * 0.28f)
                    c.drawPath(path, paint)
                }
                else -> { // "up"
                    c.drawLine(cx, cy + s * 0.4f, cx, cy - s * 0.4f, paint)
                    path.moveTo(cx - s * 0.3f, cy - s * 0.1f)
                    path.lineTo(cx, cy - s * 0.42f)
                    path.lineTo(cx + s * 0.3f, cy - s * 0.1f)
                    c.drawPath(path, paint)
                }
            }
        }
    }

    /** Item of the floating nav pill: icon + label; the selected one sits in a glass lens and takes the highlight colour. */
    class NavItem(ctx: Context, private val kind: String, label: String) : LinearLayout(ctx) {
        private val icon = IconView(ctx)
        private val tv = TextView(ctx)
        private var picked = false

        init {
            orientation = VERTICAL
            gravity = Gravity.CENTER
            isClickable = true
            setPadding(0, Ui.dp(7), 0, Ui.dp(6))
            addView(icon, LayoutParams(Ui.dp(40), Ui.dp(24)))
            tv.text = label
            tv.textSize = 10f
            tv.gravity = Gravity.CENTER
            tv.maxLines = 1
            tv.setPadding(0, Ui.dp(2), 0, 0)
            addView(tv, LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT))
            select(false)
        }

        fun select(sel: Boolean) {
            val becameSelected = sel && !picked && isLaidOut
            picked = sel
            if (becameSelected) {
                // 0.37.13: soft pop of the glyph and a fade-in of the label when a tab becomes the selected one
                icon.scaleX = 0.78f
                icon.scaleY = 0.78f
                icon.animate().scaleX(1f).scaleY(1f).setDuration(260)
                    .setInterpolator(android.view.animation.OvershootInterpolator(2.4f)).start()
                tv.alpha = 0.3f
                tv.animate().alpha(1f).setDuration(220).start()
            }
            icon.setup(kind, if (sel) Ui.p.hi else Ui.p.sub, 0)
            tv.setTextColor(if (sel) Ui.p.hi else Ui.p.sub)
            tv.typeface = if (sel) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
            background = if (sel) GlassDrawable(40, Ui.p.sel, true, false) else null
        }
    }

    /** Card rows: round icon (folder / file / class / severity shield) + first line bold, the rest smaller. */
    class RowAdapter(private val ctx: Context, private val labels: List<String>) : BaseAdapter() {
        override fun getCount(): Int = labels.size
        override fun getItem(position: Int): Any = labels[position]
        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val frame: FrameLayout
            val icon: IconView
            val tv: TextView
            val badge: TextView
            if (convertView is FrameLayout && convertView.tag == "row") {
                frame = convertView
                val card = frame.getChildAt(0) as LinearLayout
                icon = card.getChildAt(0) as IconView
                tv = card.getChildAt(1) as TextView
                badge = card.getChildAt(2) as TextView
            } else {
                frame = FrameLayout(ctx)
                frame.tag = "row"
                frame.setPadding(0, Ui.dp(3), 0, Ui.dp(3))
                val card = LinearLayout(ctx)
                card.orientation = LinearLayout.HORIZONTAL
                card.gravity = Gravity.CENTER_VERTICAL
                card.background = Ui.ripple(GlassDrawable(18, Ui.p.surface, true, false), 18)
                icon = IconView(ctx)
                val ilp = LinearLayout.LayoutParams(Ui.dp(36), Ui.dp(36))
                ilp.setMargins(Ui.dp(10), Ui.dp(7), 0, Ui.dp(7))
                card.addView(icon, ilp)
                tv = TextView(ctx)
                tv.textSize = 13f
                tv.setPadding(Ui.dp(12), Ui.dp(9), Ui.dp(8), Ui.dp(9))
                card.addView(tv, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                badge = TextView(ctx)
                badge.textSize = 9.5f
                badge.typeface = Typeface.DEFAULT_BOLD
                badge.gravity = Gravity.CENTER
                badge.setPadding(Ui.dp(7), Ui.dp(3), Ui.dp(7), Ui.dp(3))
                badge.visibility = View.GONE
                val blp = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                blp.setMargins(0, 0, Ui.dp(2), 0)
                card.addView(badge, blp)
                val chev = IconView(ctx)
                chev.setup("chev", Ui.p.sub, 0)
                val clp = LinearLayout.LayoutParams(Ui.dp(26), Ui.dp(26))
                clp.setMargins(0, 0, Ui.dp(8), 0)
                card.addView(chev, clp)
                frame.addView(card, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            }

            val label = labels[position]
            val m = Ui.sevRe.find(label)
            var kind = "code"
            var sevName = ""
            var fg = Ui.p.tintText
            var bg = Ui.alpha(Ui.p.tintText, 0x26)
            when {
                m != null -> {
                    val sc = Ui.sevColor(m.groupValues[1])
                    kind = "shield"; fg = sc; bg = Ui.alpha(sc, 0x26)
                    sevName = m.groupValues[1]
                }
                label.startsWith("📁") -> { kind = "folder"; fg = Ui.p.accent; bg = Ui.alpha(Ui.p.accent, 0x33) }
                label.startsWith("📄") -> {
                    val fname = label.removePrefix("📄").trim().substringBefore('\n').lowercase()
                    if (fname.endsWith(".dex") || fname.endsWith(".smali")) { kind = "code"; fg = 0xFF8C7BFF.toInt(); bg = Ui.alpha(fg, 0x2E) }
                    else if (fname.endsWith(".so") || fname.endsWith(".arsc") || fname.endsWith(".bin")) { kind = "cube"; fg = Ui.p.accent; bg = Ui.alpha(fg, 0x2E) }
                    else kind = "doc"
                }
                label.startsWith("⬆") -> { kind = "up" }
                label.startsWith("Show all") -> { kind = "up"; fg = Ui.p.accent; bg = Ui.alpha(Ui.p.accent, 0x33) }
            }
            icon.setup(kind, fg, bg)

            var text = label.replaceFirst(rx("^(📁|📄|⬆)\\s*"), "")
            if (sevName.isNotEmpty()) {
                // 0.37.13: the severity moves out of the title into a coloured badge
                text = text.replaceFirst(Ui.sevRe, "").trimStart().replace("\n   ", "\n")
                val sc = Ui.sevColor(sevName)
                badge.text = when (sevName) { "CRITICAL" -> "CRIT"; "MEDIUM" -> "MED"; else -> sevName }
                badge.setTextColor(sc)
                badge.background = Ui.rr(Ui.alpha(sc, 0x2E), 9)
                badge.visibility = View.VISIBLE
            } else {
                badge.visibility = View.GONE
            }
            if (kind == "code") {
                val mark = if (text.startsWith("✏ ")) "✏ " else ""
                val body = text.removePrefix(mark)
                if (body.indexOf('\n') < 0 && !body.contains(' ')) {
                    val dot = body.lastIndexOf('.')
                    if (dot > 0 && dot < body.length - 1) text = mark + body.substring(dot + 1) + "\n" + body.substring(0, dot)
                }
            }
            val nl = text.indexOf('\n')
            val firstEnd = if (nl < 0) text.length else nl
            val sb = SpannableStringBuilder(text)
            val flags = Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            if (firstEnd > 0) {
                sb.setSpan(ForegroundColorSpan(Ui.p.ink), 0, firstEnd, flags)
                if (nl >= 0 || kind == "folder") sb.setSpan(StyleSpan(Typeface.BOLD), 0, firstEnd, flags)
            }
            if (nl >= 0 && nl + 1 < text.length) {
                sb.setSpan(ForegroundColorSpan(Ui.p.sub), nl, text.length, flags)
                sb.setSpan(AbsoluteSizeSpan(12, true), nl, text.length, flags)
                if (label.startsWith("📄") && text.endsWith(" MB")) {
                    sb.setSpan(ForegroundColorSpan(Ui.p.accent), nl, text.length, flags)   // big file
                    sb.setSpan(StyleSpan(Typeface.BOLD), nl, text.length, flags)
                }
            }
            tv.text = sb
            return frame
        }
    }

    // ---------- hero decoration ----------

    /**
     * Header art (0.37.9). Slim mode (showArt = false): nothing, the ambient field shows through. Welcome mode
     * (showArt = true): a soft glow and one glass tile with the code glyph, centred between the title block and
     * the buttons. Replaces the old flat illustration.
     */
    class HeroArt(ctx: Context) : View(ctx) {
        var showArt = true
        var bottomInset = 0
            set(v) { field = v; invalidate() }
        private val fill = Paint(Paint.ANTI_ALIAS_FLAG)
        private val line = Paint(Paint.ANTI_ALIAS_FLAG)
        private val tile = GlassDrawable(36, Ui.p.glassHi)
        private val pill = GlassDrawable(20, Ui.p.glassHi, true, false)
        private val txt = Paint(Paint.ANTI_ALIAS_FLAG)

        // Never ask for more height than the header needs (see 0.24.1): 0 unless the parent gives an exact size.
        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            val w = MeasureSpec.getSize(widthMeasureSpec)
            val h = if (MeasureSpec.getMode(heightMeasureSpec) == MeasureSpec.EXACTLY) MeasureSpec.getSize(heightMeasureSpec) else 0
            setMeasuredDimension(w, h)
        }

        override fun onDraw(c: Canvas) {
            val w = width.toFloat()
            val h = height.toFloat()
            if (w <= 0f || h <= 0f || !showArt) return
            val panelTop = h - Ui.dp(176) - bottomInset
            val top = Ui.dp(200).toFloat()
            val room = panelTop - top
            if (room < Ui.dp(120)) return
            val size = minOf(Ui.dp(124).toFloat(), room * 0.7f)
            val cx = w / 2f
            val cy = top + room / 2f

            // glow behind the tile
            val gr = size * 1.5f
            fill.style = Paint.Style.FILL
            fill.color = Color.BLACK
            fill.shader = RadialGradient(cx, cy, gr, Ui.alpha(Ui.p.glow1, 0x80), Ui.alpha(Ui.p.glow1, 0), Shader.TileMode.CLAMP)
            c.drawCircle(cx, cy, gr, fill)
            fill.shader = RadialGradient(cx + size * 0.35f, cy + size * 0.4f, gr * 0.6f, Ui.alpha(Ui.p.glow2, 0x4A), Ui.alpha(Ui.p.glow2, 0), Shader.TileMode.CLAMP)
            c.drawCircle(cx + size * 0.35f, cy + size * 0.4f, gr * 0.6f, fill)
            fill.shader = null

            // glass tile
            val half = size / 2f
            tile.setBounds((cx - half).toInt(), (cy - half).toInt(), (cx + half).toInt(), (cy + half).toInt())
            tile.draw(c)

            // </> glyph
            val s = size * 0.46f
            line.style = Paint.Style.STROKE
            line.strokeWidth = size * 0.058f
            line.strokeCap = Paint.Cap.ROUND
            line.strokeJoin = Paint.Join.ROUND
            line.color = Ui.p.hi
            val path = Path()
            path.moveTo(cx - s * 0.16f, cy - s * 0.3f)
            path.lineTo(cx - s * 0.46f, cy)
            path.lineTo(cx - s * 0.16f, cy + s * 0.3f)
            path.moveTo(cx + s * 0.16f, cy - s * 0.3f)
            path.lineTo(cx + s * 0.46f, cy)
            path.lineTo(cx + s * 0.16f, cy + s * 0.3f)
            c.drawPath(path, line)
            line.color = Ui.alpha(Ui.p.heroInk, 0xB0)
            c.drawLine(cx + s * 0.08f, cy - s * 0.36f, cx - s * 0.08f, cy + s * 0.36f, line)

            // three feature capsules under the tile (only when there is room)
            val tags = arrayOf("Smali", "Manifest", "Security")
            val ph = Ui.dp(32).toFloat()
            val py = cy + half + Ui.dp(26)
            if (py + ph < panelTop) {
                txt.textSize = Ui.dp(12).toFloat()
                txt.textAlign = Paint.Align.CENTER
                txt.color = Ui.alpha(Ui.p.heroInk, 0xD0)
                val gap = Ui.dp(8).toFloat()
                val ws = FloatArray(tags.size)
                var total = gap * (tags.size - 1)
                for (i in tags.indices) { ws[i] = txt.measureText(tags[i]) + Ui.dp(28); total += ws[i] }
                var x = cx - total / 2f
                for (i in tags.indices) {
                    pill.setBounds(x.toInt(), py.toInt(), (x + ws[i]).toInt(), (py + ph).toInt())
                    pill.draw(c)
                    c.drawText(tags[i], x + ws[i] / 2f, py + ph / 2f + Ui.dp(4), txt)
                    x += ws[i] + gap
                }
            }
        }
    }
}
