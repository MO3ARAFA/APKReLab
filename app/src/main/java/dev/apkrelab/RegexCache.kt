package dev.apkrelab

import java.util.concurrent.ConcurrentHashMap

private val rxCache = ConcurrentHashMap<String, Regex>()

/**
 * 0.37.6: compiled-regex cache. The scanners used to build ~100 Regex objects PER CLASS (SecurityScanner.scanSmali, AndroGoatChecks.scan),
 * i.e. millions of compilations on a big APK. Every call site passes a constant pattern, so the cache stays small (about 150 entries).
 * Never pass user input or a per-class string here (it would grow without limit): use Regex(...) for those.
 */
internal fun rx(pattern: String, vararg options: RegexOption): Regex {
    val key = if (options.isEmpty()) pattern else pattern + "\u0000" + options.joinToString(",")
    return rxCache.getOrPut(key) { if (options.isEmpty()) Regex(pattern) else Regex(pattern, options.toSet()) }
}
