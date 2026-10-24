package dev.apkrelab

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** 0.37.5: an image or PDF attached in the AI Hub chat (already downscaled / size-checked by Attachments), base64 without line breaks. */
class Media(val name: String, val mime: String, val b64: String)

/** Provider abstraction: add OpenAI / Claude later by implementing this interface. */
interface AiProvider {
    /** Blocking call - run on a background thread. If onPartial is given, the answer is streamed and onPartial receives the full text so far. [media] = images / PDFs sent with the prompt (only providers that support them get a non-empty list). */
    fun complete(prompt: String, onPartial: ((String) -> Unit)? = null, media: List<Media> = emptyList()): String
}

class GeminiProvider(private val apiKey: String, private val model: String) : AiProvider {

    override fun complete(prompt: String, onPartial: ((String) -> Unit)?, media: List<Media>): String {
        val streaming = onPartial != null
        val url = URL("https://generativelanguage.googleapis.com/v1beta/models/$model:" +
            if (streaming) "streamGenerateContent?alt=sse" else "generateContent")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 20_000
            conn.readTimeout = 120_000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("x-goog-api-key", apiKey)

            val partsArr = JSONArray()
            for (m in media) {   // 0.37.5: images / PDFs first, then the text (Gemini reads them in order)
                partsArr.put(JSONObject().put("inline_data", JSONObject().put("mime_type", m.mime).put("data", m.b64)))
            }
            partsArr.put(JSONObject().put("text", prompt))
            val body = JSONObject().put("contents", JSONArray().put(JSONObject().put("parts", partsArr)))
            conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }

            val code = conn.responseCode
            if (streaming && code in 200..299) {
                // 0.16.0: SSE - lines "data: {json}", each with the next piece of text
                val sb = StringBuilder()
                var lastRaw = ""
                conn.inputStream.bufferedReader(Charsets.UTF_8).use { r ->
                    while (true) {
                        val line = r.readLine() ?: break
                        if (!line.startsWith("data:")) continue
                        val payload = line.substring(5).trim()
                        if (payload.isEmpty() || payload == "[DONE]") continue
                        lastRaw = payload
                        val j = try { JSONObject(payload) } catch (_: Throwable) { continue }
                        val cands = j.optJSONArray("candidates") ?: continue
                        if (cands.length() == 0) continue
                        val parts = cands.getJSONObject(0).optJSONObject("content")?.optJSONArray("parts") ?: continue
                        var added = false
                        for (i in 0 until parts.length()) {
                            val t = parts.getJSONObject(i).optString("text")
                            if (t.isNotEmpty()) { sb.append(t); added = true }
                        }
                        if (added) onPartial!!.invoke(sb.toString())
                    }
                }
                if (sb.isBlank()) throw RuntimeException("Empty answer: " + lastRaw.take(300))
                return sb.toString()
            }
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""

            if (code !in 200..299) {
                val msg = try {
                    JSONObject(text).getJSONObject("error").getString("message")
                } catch (_: Throwable) { text.take(300) }
                throw RuntimeException("HTTP $code: $msg")
            }

            val json = JSONObject(text)
            val candidates = json.optJSONArray("candidates")
            if (candidates == null || candidates.length() == 0) {
                throw RuntimeException("No answer returned: " + text.take(300))
            }
            val parts = candidates.getJSONObject(0).optJSONObject("content")?.optJSONArray("parts")
                ?: throw RuntimeException("Empty answer: " + text.take(300))
            val sb = StringBuilder()
            for (i in 0 until parts.length()) sb.append(parts.getJSONObject(i).optString("text"))
            return sb.toString().ifBlank { "(empty response)" }
        } finally {
            conn.disconnect()
        }
    }
}

/** 0.27.0: any OpenAI-compatible /chat/completions endpoint (Groq, OpenRouter, Mistral, ...). Same error format as GeminiProvider ("HTTP code: message"). */
class OpenAiCompatProvider(private val baseUrl: String, private val apiKey: String, private val model: String) : AiProvider {

    override fun complete(prompt: String, onPartial: ((String) -> Unit)?, media: List<Media>): String {
        val streaming = onPartial != null
        val conn = URL(baseUrl.trimEnd('/') + "/chat/completions").openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 20_000
            conn.readTimeout = 120_000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Authorization", "Bearer $apiKey")
            conn.setRequestProperty("X-Title", "APK ReLab")

            val images = media.filter { it.mime.startsWith("image/") }
            val userContent: Any = if (images.isEmpty()) prompt else JSONArray().apply {
                put(JSONObject().put("type", "text").put("text", prompt))
                for (m in images) put(JSONObject().put("type", "image_url").put("image_url", JSONObject().put("url", "data:" + m.mime + ";base64," + m.b64)))
            }
            val body = JSONObject()
                .put("model", model)
                .put("messages", JSONArray().put(JSONObject().put("role", "user").put("content", userContent)))
                .put("stream", streaming)
            conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }

            val code = conn.responseCode
            if (streaming && code in 200..299) {
                val sb = StringBuilder()
                var lastRaw = ""
                conn.inputStream.bufferedReader(Charsets.UTF_8).use { r ->
                    while (true) {
                        val line = r.readLine() ?: break
                        if (!line.startsWith("data:")) continue
                        val payload = line.substring(5).trim()
                        if (payload.isEmpty() || payload == "[DONE]") continue
                        lastRaw = payload
                        val j = try { JSONObject(payload) } catch (_: Throwable) { continue }
                        val choices = j.optJSONArray("choices") ?: continue
                        if (choices.length() == 0) continue
                        val delta = choices.getJSONObject(0).optJSONObject("delta") ?: continue
                        if (delta.isNull("content")) continue
                        val t = delta.optString("content")
                        if (t.isNotEmpty()) {
                            sb.append(t)
                            onPartial!!.invoke(sb.toString())
                        }
                    }
                }
                if (sb.isBlank()) throw RuntimeException("Empty answer: " + lastRaw.take(300))
                return sb.toString()
            }
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (code !in 200..299) {
                val msg = try {
                    JSONObject(text).getJSONObject("error").getString("message")
                } catch (_: Throwable) { text.take(300) }
                throw RuntimeException("HTTP $code: $msg")
            }
            val json = JSONObject(text)
            val choices = json.optJSONArray("choices")
            if (choices == null || choices.length() == 0) throw RuntimeException("No answer returned: " + text.take(300))
            val msgObj = choices.getJSONObject(0).optJSONObject("message")
            val content = if (msgObj == null || msgObj.isNull("content")) "" else msgObj.optString("content")
            return content.ifBlank { "(empty response)" }
        } finally {
            conn.disconnect()
        }
    }
}

/** Stores the API key encrypted with an Android Keystore AES-GCM key (no extra libraries). */
object SecureStore {
    private const val ALIAS = "apkrelab_key"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    fun encrypt(plain: String): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        val ct = c.doFinal(plain.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(c.iv + ct, Base64.NO_WRAP)
    }

    fun decrypt(stored: String): String? = try {
        val all = Base64.decode(stored, Base64.NO_WRAP)
        val iv = all.copyOfRange(0, 12)
        val ct = all.copyOfRange(12, all.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        String(c.doFinal(ct), Charsets.UTF_8)
    } catch (_: Throwable) {
        null
    }
}
