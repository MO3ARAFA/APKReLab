package dev.apkrelab

import android.content.SharedPreferences
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** One AI provider the user can add a key for. Gemini keeps the old pref names ("k", "model") so existing keys keep working. */
class ProviderSpec(
    val id: String,
    val label: String,
    val baseUrl: String,          // OpenAI-compatible base URL; empty for Gemini
    val defaultModel: String,
    val fallbackModel: String,    // "" = none
    val keyPref: String,
    val modelPref: String,
    val maxPromptChars: Int,      // providers with small free limits are skipped for bigger prompts
    val keyHint: String
)

class ChainItem(val spec: ProviderSpec, val key: String, val model: String)

class AiResult(val text: String, val label: String, val notes: String, val fromCache: Boolean)

/** 0.27.0: provider registry + ordered fallback chain (primary first, then the other providers that have a key). */
object AiHub {
    val specs = listOf(
        ProviderSpec("gemini", "Gemini", "", "gemini-3.6-flash", "gemini-3.5-flash-lite",
            "k", "model", 400_000, "Gemini API key (aistudio.google.com)"),
        ProviderSpec("groq", "Groq", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "llama-3.1-8b-instant",
            "k_groq", "model_groq", 24_000, "Groq API key (console.groq.com)"),
        ProviderSpec("openrouter", "OpenRouter", "https://openrouter.ai/api/v1", "openrouter/free", "",
            "k_openrouter", "model_openrouter", 60_000, "OpenRouter API key (openrouter.ai)")
    )

    fun primaryId(p: SharedPreferences): String = p.getString("primary", "gemini") ?: "gemini"

    // Old defaults that no longer work: treated as "not set" so the new default applies without the user editing anything.
    private val legacyModels = setOf("meta-llama/llama-3.3-70b-instruct:free")

    fun model(p: SharedPreferences, s: ProviderSpec): String {
        val m = (p.getString(s.modelPref, s.defaultModel) ?: s.defaultModel).trim()
        return if (m.isEmpty() || m in legacyModels) s.defaultModel else m
    }

    /** Models that returned 404 (gone) or a quota 429 are skipped for a while, so loops like AI triage do not waste a failed call on each item. */
    internal val cooldown = java.util.concurrent.ConcurrentHashMap<String, Long>()

    fun key(p: SharedPreferences, s: ProviderSpec): String? =
        p.getString(s.keyPref, null)?.let { SecureStore.decrypt(it) }?.takeIf { it.isNotEmpty() }

    /** 0.32.0: the primary provider (default Gemini) first, then the others in the order of the provider list (OpenRouter/Groq are optional backups: no key = skipped). If the saved primary has no key, Gemini (or the first provider with a key) leads. */
    fun chain(p: SharedPreferences): List<ChainItem> {
        val all = specs.mapNotNull { s -> key(p, s)?.let { ChainItem(s, it, model(p, s)) } }
        val saved = primaryId(p)
        val pid = if (all.any { it.spec.id == saved }) saved else "gemini"
        return all.sortedBy { if (it.spec.id == pid) 0 else 1 }
    }

    fun anyKey(p: SharedPreferences): String? = chain(p).firstOrNull()?.key

    /** Used as the "model" part of the cache key. */
    fun cacheModel(p: SharedPreferences): String {
        val c = chain(p).firstOrNull() ?: return "none"
        return c.spec.id + ":" + c.model
    }

    /** Ordered free OpenRouter models (strongest first), one id per line, edited in AI settings. */
    fun orList(p: SharedPreferences): List<String> =
        (p.getString("or_free_list", "") ?: "").lines().map { it.trim() }.filter { it.isNotEmpty() }

    // My own judgement of strength (largest / newest first), NOT a benchmark. Matched against the model name from OpenRouter; unknown free models go after these, by context size. The owner can reorder the list in settings.
    private val rankOrder = listOf(
        "nemotron 3 ultra", "laguna s 2.1", "nemotron 3 super", "inkling", "dots3-note preview",
        "ling 3.0 flash sante", "gemma 4 31b", "nemotron 3.5 lightning", "inkling small", "north mini code",
        "gemma 4 26b a4b", "apodex 1.1 mini", "nemotron 3 nano omni", "laguna xs 2.1"
    )

    private class FreeModel(val id: String, val rank: Int, val ctx: Int)

    /** Blocking, no key needed: reads OpenRouter's public model list, keeps text-only models that cost $0 and have >= 100k context. */
    fun fetchFreeModels(): List<String> {
        val conn = URL("https://openrouter.ai/api/v1/models").openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 20_000
            conn.readTimeout = 60_000
            val code = conn.responseCode
            if (code !in 200..299) throw RuntimeException("HTTP $code")
            val text = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            val arr = JSONObject(text).getJSONArray("data")
            val bad = rx("embed|rerank|safety|guard|image|ming|audio|tts|whisper", RegexOption.IGNORE_CASE)
            val out = ArrayList<FreeModel>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val id = o.optString("id")
                if (id.isEmpty() || id == "openrouter/free") continue
                val name = o.optString("name")
                val pr = o.optJSONObject("pricing") ?: continue
                val free = (pr.optString("prompt", "1").toDoubleOrNull() ?: 1.0) == 0.0 &&
                    (pr.optString("completion", "1").toDoubleOrNull() ?: 1.0) == 0.0
                if (!free) continue
                if (bad.containsMatchIn(name) || bad.containsMatchIn(id)) continue
                val outMods = o.optJSONObject("architecture")?.optJSONArray("output_modalities")
                if (outMods != null) {
                    var textOnly = outMods.length() > 0
                    for (k in 0 until outMods.length()) if (outMods.optString(k) != "text") textOnly = false
                    if (!textOnly) continue
                }
                val ctx = o.optInt("context_length", 0)
                if (ctx < 100_000) continue
                val norm = name.substringAfter(": ").replace("(free)", "").trim().lowercase()
                val r = rankOrder.indexOf(norm)
                out.add(FreeModel(id, if (r < 0) 1000 else r, ctx))
            }
            return out.sortedWith(compareBy<FreeModel>({ it.rank }, { -it.ctx })).map { it.id }
        } finally {
            conn.disconnect()
        }
    }

    internal val providerCooldown = java.util.concurrent.ConcurrentHashMap<String, Long>()

    internal fun make(item: ChainItem, model: String): AiProvider =
        if (item.spec.id == "gemini") GeminiProvider(item.key, model)
        else OpenAiCompatProvider(item.spec.baseUrl, item.key, model)

    /** Blocking. Tries each provider (and its fallback model) with one retry on busy errors. Throws RuntimeException(message). */
    fun call(p: SharedPreferences, prompt: String, cache: Boolean, onPartial: ((String) -> Unit)?, status: (String) -> Unit): AiResult =
        callImpl(p, prompt, cache, onPartial, emptySet(), status)

    /**
     * 0.29.0 (council): like call() without cache, but models whose "Provider/model" label is in [avoid] are skipped, so a DIFFERENT model answers.
     * If no other model can answer, it falls back to any model and says so in the notes (a same-model review is better than none).
     */
    fun callAvoiding(p: SharedPreferences, prompt: String, avoid: Set<String>, status: (String) -> Unit): AiResult {
        val clean = avoid.filter { it.isNotBlank() }.toSet()
        if (clean.isNotEmpty()) {
            try {
                return callImpl(p, prompt, false, null, clean, status)
            } catch (_: Throwable) { }
        }
        val r = callImpl(p, prompt, false, null, emptySet(), status)
        val note = if (clean.isEmpty()) r.notes else (r.notes + "\n(no different model was available)").trim()
        return AiResult(r.text, r.label, note, false)
    }

    private fun callImpl(p: SharedPreferences, prompt: String, cache: Boolean, onPartial: ((String) -> Unit)?, avoid: Set<String>, status: (String) -> Unit): AiResult {
        val chain = chain(p)
        if (chain.isEmpty()) throw RuntimeException("No API key saved")
        val ck = if (cache) AiCache.key(cacheModel(p), prompt) else null
        if (ck != null) {
            val hit = AiCache.get(ck)
            if (hit != null) {
                if (hit.startsWith("MODEL:")) {
                    val nl = hit.indexOf('\n')
                    val label = hit.substring(6, if (nl < 0) hit.length else nl)
                    return AiResult(if (nl < 0) "" else hit.substring(nl + 1), label, "", true)
                }
                return AiResult(hit, "", "", true)
            }
        }
        val notes = ArrayList<String>()
        var lastErr = ""
        for ((ci, item) in chain.withIndex()) {
            if (prompt.length > item.spec.maxPromptChars) {
                notes.add(item.spec.label + ": skipped (prompt too large for its free limits)")
                lastErr = item.spec.label + ": prompt too large"
                continue
            }
            if ((providerCooldown[item.spec.id] ?: 0L) > System.currentTimeMillis()) {
                notes.add(item.spec.label + ": skipped (daily limit reached, retrying later)")
                if (lastErr.isEmpty()) lastErr = item.spec.label + ": daily limit reached"
                continue
            }
            val isOr = item.spec.id == "openrouter"
            // OpenRouter: the owner's ordered free list first (max 8 tries), then the configured model (default openrouter/free) as the last resort.
            val models = (if (isOr) orList(p).take(8) + listOf(item.model) else listOf(item.model, item.spec.fallbackModel))
                .filter { it.isNotBlank() }.distinct()
            var giveUpProvider = false
            for (m in models) {
                if (giveUpProvider) break
                if ((item.spec.label + "/" + m) in avoid) continue
                val cdKey = item.spec.id + "/" + m
                val cdUntil = cooldown[cdKey] ?: 0L
                if (cdUntil > System.currentTimeMillis()) {
                    notes.add(item.spec.label + "/" + m + ": skipped (unavailable/quota, retrying later)")
                    if (lastErr.isEmpty()) lastErr = item.spec.label + "/" + m + " is unavailable right now"
                    continue
                }
                for (attempt in 1..2) {
                    status("Thinking... (${item.spec.label}/$m - attempt $attempt)")
                    try {
                        val r = make(item, m).complete(prompt, onPartial)
                        val label = item.spec.label + "/" + m
                        if (ck != null && ci == 0 && (m == item.model || isOr)) AiCache.put(ck, "MODEL:" + label + "\n" + r)  // only primary-model answers are cached
                        return AiResult(r, label, notes.joinToString("\n"), false)
                    } catch (t: Throwable) {
                        lastErr = t.message ?: t.javaClass.simpleName
                        notes.add(item.spec.label + "/" + m + ": " + lastErr.take(90))
                        val busy = lastErr.startsWith("HTTP 503") || lastErr.startsWith("HTTP 429") ||
                            lastErr.startsWith("HTTP 500") || lastErr.startsWith("HTTP 504") ||
                            t is java.net.SocketTimeoutException
                        if (lastErr.startsWith("HTTP 404")) {                          // model gone: skip it for an hour, try the fallback model
                            cooldown[cdKey] = System.currentTimeMillis() + 3_600_000L
                            break
                        }
                        if (lastErr.startsWith("HTTP 429") && lastErr.contains("quota", ignoreCase = true)) {   // daily quota is used up: retrying is pointless
                            cooldown[cdKey] = System.currentTimeMillis() + 600_000L
                            break
                        }
                        if (lastErr.contains("per-day", ignoreCase = true) || lastErr.contains("daily", ignoreCase = true)) {
                            providerCooldown[item.spec.id] = System.currentTimeMillis() + 1_800_000L   // account-wide daily cap: all its models would fail
                            giveUpProvider = true
                            break
                        }
                        if (isOr && !lastErr.startsWith("HTTP 401")) {                 // OpenRouter: any model-level failure -> next free model
                            cooldown[cdKey] = System.currentTimeMillis() + (if (busy) 60_000L else 600_000L)
                            break
                        }
                        if (busy && attempt == 1) { Thread.sleep(2500); continue }      // retry once
                        if (busy) break                                                // still busy: next model
                        giveUpProvider = true                                          // bad key / bad request: next provider
                        break
                    }
                }
            }
        }
        throw RuntimeException(lastErr.ifEmpty { "All providers failed" })
    }
}
