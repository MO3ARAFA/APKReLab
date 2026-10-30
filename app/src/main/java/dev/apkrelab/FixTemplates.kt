package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding

/**
 * 1.2.0: one-sentence fixes for the card shapes whose right change is known and local. Not a patch and not AI: a sentence the reader turns into code, with the API it is
 * about. Matched on the card's rule id and, for data-flow cards, on the sink the detail names ("reaches FileOutputStream.<init>()"): a File READ never gets the file WRITE
 * sentence. A card no template matches keeps its own recommendation only.
 */
object FixTemplates {
    class Fix(val id: String, val sentence: String, val api: String)

    private val sinkRe = Regex("reaches ([A-Za-z0-9_$]+\\.[A-Za-z0-9_$<>]+)\\(\\)")

    /** The sink API a data-flow card names ("FileOutputStream.<init>"), or null. */
    fun sinkOf(f: Finding): String? = sinkRe.find(f.detail)?.groupValues?.get(1)

    private val fileWrites = setOf("FileOutputStream.<init>", "FileWriter.<init>", "RandomAccessFile.<init>", "Files.write", "Files.newOutputStream", "File.delete",
        "File.renameTo", "File.createNewFile", "File.mkdirs", "File.mkdir")
    private val taintRules = setOf("taint-flow", "taint-xclass", "taint")

    /** [pkg] = the app's package (for the permission name of the exported-component template). */
    fun match(f: Finding, pkg: String = ""): Fix? {
        val sink = sinkOf(f)
        val taint = f.ruleId in taintRules || f.ruleId.startsWith("taint")
        return when {
            (taint && (f.title.contains("loaded into a WebView") || sink == "WebView.loadUrl")) || f.ruleId == "webview-intent-url" ->
                Fix("webview-url", "Load only HTTPS URLs from an allow-list, or validate the host before loadUrl().", "WebView.loadUrl / Uri.getHost")
            (taint && f.title.contains("used as a file path") && sink != null && sink in fileWrites) || f.ruleId == "zip-slip" ->
                Fix("file-write", "Resolve the path against a fixed directory, call getCanonicalPath() and reject it unless it still starts with that directory (no \"..\").", "File.getCanonicalPath")
            (taint && f.title.contains("SQL statement")) || f.ruleId == "sql-concat" || f.ruleId == "provider-sql-injection" ->
                Fix("sql-args", "Use SQLiteDatabase.rawQuery(sql, args) / query(..., selectionArgs) with ? placeholders instead of building the SQL text.", "SQLiteDatabase.rawQuery(String, String[])")
            f.ruleId == "tls-trustmanager" ->
                Fix("trustmanager", "Remove the TrustManager and use the platform default; if pinning is required, use OkHttp's CertificatePinner or a network security config pin-set.", "CertificatePinner / network_security_config")
            f.ruleId == "webview-js-interface" || f.ruleId == "webview-js-bridge-method" ->
                Fix("js-bridge", "Remove the @JavascriptInterface annotation from methods the page does not need, or restrict the loaded pages to HTTPS + an allow-list.", "WebView.addJavascriptInterface")
            f.ruleId == "manifest-exported-components" ->
                Fix("exported", "Add android:permission=\"" + (if (pkg.isEmpty()) "<package>" else pkg) + ".permission.<NAME>\" with protectionLevel=\"signature\", or set android:exported=\"false\" (the AI Hub's queue_manifest_fix does the second).",
                    "android:permission / android:exported")
            else -> null
        }
    }
}
