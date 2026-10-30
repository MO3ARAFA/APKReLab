package dev.apkrelab

/**
 * 0.86.0: positive evidence that a hardcoded secret-looking value is USED as a secret. Before 0.86.0 a credential-like NAME plus a random-looking
 * VALUE was enough for HIGH, and every new real-app set showed a new family of public strings that look like that (thread names, header names,
 * Compose source info, class names...). From 0.86.0 the two name/shape detectors (`secrets-sensitive-fields`, `high-entropy-strings`) give HIGH
 * only when the value reaches a secret sink in the same method: a key / IV spec, Cipher / Mac init, a KeyStore password, an Authorization
 * header, HTTP basic credentials, a JWT signer. Known key FORMATS (JWT, AWS, Google API keys, PEM ...) are their own rules and are unchanged.
 * This is co-occurrence in one method, not a data-flow proof; the card says which sink it saw.
 */
internal object SecretEvidence {

    private val sinks: List<Pair<Regex, String>> = listOf(
        Regex("Ljavax/crypto/spec/(?:SecretKeySpec|DESKeySpec|DESedeKeySpec|PBEKeySpec);-><init>") to "a cryptographic key (KeySpec)",
        Regex("Ljavax/crypto/spec/(?:IvParameterSpec|GCMParameterSpec);-><init>") to "an IV / nonce",
        Regex("Ljavax/crypto/(?:Cipher|Mac);->init\\(") to "a Cipher / Mac key",
        Regex("Ljava/security/KeyStore;->(?:load|getKey)\\(") to "a KeyStore password",
        Regex("Lokhttp3/Credentials;->basic\\(|Ljava/net/PasswordAuthentication;-><init>|->setBasicAuth\\(") to "HTTP credentials",
        Regex("Lio/jsonwebtoken/|Lcom/auth0/jwt/algorithms/Algorithm;->HMAC") to "a JWT signing key"
    )
    private val authHeader = Regex("const-string(?:/jumbo)? [vp]\\d+, \"(?i:authorization|x-api-key|api-key|apikey)\"")
    private val headerCall = Regex("->(?:addHeader|header|setRequestProperty|addRequestProperty|set)\\(")

    // an API key in a query parameter named like one (?appid= / &apikey= / key= / access_token=)
    // the name ENDS like a credential: key, apikey, api_key, appid, token, auth_token, access_token, client_secret (Allsafe NoteReceiver: auth_token)
    private val keyParamName = Regex("const-string(?:/jumbo)? [vp]\\d+, \"(?i:[a-z0-9]*[_-]?(?:token|api[_-]?key|apikey|key|secret|appid|app_id|auth))\"")
    private val queryCall = Regex("->(?:addQueryParameter|addEncodedQueryParameter|appendQueryParameter|setQueryParameter)\\(")

    /** The sink a method body shows, or null. */
    fun sinkIn(body: String): String? {
        for ((re, label) in sinks) if (re.containsMatchIn(body)) return label
        if (authHeader.containsMatchIn(body) && headerCall.containsMatchIn(body)) return "an Authorization / API-key header"
        if (keyParamName.containsMatchIn(body) && queryCall.containsMatchIn(body)) return "an API-key query parameter"
        return null
    }

    /**
     * A token FORMAT that is a credential by construction and that the known-format rules do not cover. 0.86.0 (Breezy `uu`, a weather
     * provider key "1|<40 chars>" that 0.86.0 would otherwise have lowered): a Laravel Sanctum personal access token, `<id>|<40 alphanumerics>`.
     */
    fun formatOf(value: String): String? =
        if (Regex("^\\d{1,10}\\|[A-Za-z0-9]{40}$").matches(value)) "a Laravel Sanctum access token (id|40 characters)" else null

    /** Body of the method that contains [at], or "" outside a method. */
    fun methodAround(text: String, at: Int): String {
        val a = text.lastIndexOf("\n.method ", at.coerceIn(0, text.length))
        if (a < 0) return ""
        val b = text.indexOf("\n.end method", at.coerceIn(0, text.length))
        return if (b < 0) text.substring(a) else text.substring(a, b)
    }

    /** Evidence for a literal at [at]: a sink in the same method. */
    fun forLiteral(text: String, at: Int): String? = sinkIn(methodAround(text, at))

    /**
     * Evidence for a field [name] of [classType] initialised with [value]: a method of the class that reads the field, or that holds the same
     * literal (a Kotlin / Java constant is inlined at its uses), and shows a sink.
     */
    fun forField(text: String, classType: String, name: String, value: String): String? {
        val read = Regex("get-object [vp]\\d+(?:, [vp]\\d+)?, " + Regex.escape(classType) + "->" + Regex.escape(name) + ":")
        val lit = "\"" + value + "\""
        var at = text.indexOf("\n.method ")
        while (at >= 0) {
            val end = text.indexOf("\n.end method", at).let { if (it < 0) text.length else it }
            val body = text.substring(at, end)
            if (read.containsMatchIn(body) || (body.contains("const-string") && body.contains(lit))) sinkIn(body)?.let { return it }
            at = text.indexOf("\n.method ", end)
        }
        return null
    }
}
