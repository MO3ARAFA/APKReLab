# Recall by injection on netguard (eu.faircode.netguard): 53 cases

| case | pattern | kind | expected | result | best severity | other cards for the class |
|---|---|---|---|---|---|---|
| 01 | AES key from a string constant (SecretKeySpec) | must | HIGH+ (crypto-hardcoded-key) | **DETECTED** | HIGH |  |
| 02 | bearer token and its Authorization header in the same method | must | HIGH+ (secrets-sensitive-fields/high-entropy-strings) | **DETECTED** | HIGH |  |
| 03 | the same token, the header is set in ANOTHER class (interceptor) | probe | HIGH+ (secrets-sensitive-fields/high-entropy-strings) | **DETECTED** | HIGH |  |
| 04 | AWS access key id in a string constant | must | HIGH+ (secrets-known-formats/res-strings-aws-keys) | **DETECTED** | CRITICAL | HIGH AWS access key ID embedded |
| 05 | JWT in a string constant | must | HIGH+ (secrets-known-formats/jwt-hardcoded-secret) | **DETECTED** | HIGH |  |
| 06 | Stripe live secret key | must | HIGH+ (secrets-known-formats/res-strings-known-tokens) | **DETECTED** | CRITICAL | CRITICAL Stripe live secret key embedded; HIGH Hardcoded credential: Stripe Acces |
| 07 | password written to SharedPreferences in plain text | must | MEDIUM+ (fintech-unencrypted-storage/androgoat-checks) | **DETECTED** | HIGH |  |
| 10 | trust-all TrustManager installed in an SSLContext (readable names) | must | CRITICAL+ (tls-trustmanager) | **DETECTED** | CRITICAL |  |
| 11 | trust-all TrustManager, R8 style: short names, null checks, default package | must | CRITICAL+ (tls-trustmanager) | **DETECTED** | CRITICAL |  |
| 12 | all-true HostnameVerifier installed on an HttpsURLConnection | must | HIGH+ (tls-hostname-verifier) | **DETECTED** | HIGH |  |
| 13 | trust-all TrustManager installed only when a boolean parameter is true | probe | MEDIUM+ (tls-trustmanager) | **DETECTED** | CRITICAL |  |
| 14 | SSLContext.getInstance("SSLv3") | must | HIGH+ (tls-protocol-version) | **DETECTED** | HIGH |  |
| 15 | Cipher AES/ECB/PKCS5Padding | must | HIGH+ (crypto-cipher) | **DETECTED** | HIGH |  |
| 16 | Cipher DES/CBC/PKCS5Padding | must | HIGH+ (crypto-cipher) | **DETECTED** | HIGH |  |
| 17 | MD5 of a password | must | MEDIUM+ (crypto-weak-hash) | **DETECTED** | MEDIUM |  |
| 18 | constant IV (IvParameterSpec from a constant byte array) | must | MEDIUM+ (crypto-static-iv) | **DETECTED** | MEDIUM |  |
| 19 | java.util.Random used to build a login token | must | MEDIUM+ (weak-random) | **DETECTED** | MEDIUM |  |
| 20 | RSA key pair of 512 bits | must | HIGH+ (weak-key-size) | **DETECTED** | HIGH |  |
| 35 | SecureRandom (SHA1PRNG) seeded with a constant | must | HIGH+ (crypto-sha1prng-seed) | **DETECTED** | HIGH |  |
| 21 | exported activity: Intent extra loaded into a WebView | must | HIGH+ (taint-flow/webview-intent-url) | **DETECTED** | HIGH |  |
| 22 | JavaScript bridge whose method runs a command | must | HIGH+ (webview-js-bridge-method) | **DETECTED** | HIGH | CRITICAL Untrusted input reaches a shell co; MEDIUM Shell command execution; MEDIUM WebVie |
| 23 | WebView with file access from file URLs and JavaScript | must | HIGH+ (webview-file-access) | **DETECTED** | HIGH | LOW WebView JavaScript enabled |
| 24 | WebView debugging enabled | must | MEDIUM+ (webview-debugging) | **DETECTED** | MEDIUM |  |
| 25 | exported ContentProvider concatenating the selection into rawQuery | must | HIGH+ (provider-sql-injection/sql-concat) | **DETECTED** | HIGH |  |
| 26 | exported receiver: Intent extra becomes the next startActivity | must | HIGH+ (intent-redirection/taint-flow) | **DETECTED** | HIGH |  |
| 27 | exported service: Intent extra executed as a shell command | must | CRITICAL+ (taint-flow/shell-exec) | **DETECTED** | CRITICAL |  |
| 28 | mutable PendingIntent with an empty implicit Intent | must | MEDIUM+ (pendingintent-mutable) | **DETECTED** | MEDIUM |  |
| 29 | broadcast carrying a token, sent without a receiver permission | must | MEDIUM+ (broadcast-unprotected-send) | **DETECTED** | HIGH |  |
| 30 | file created world-readable (MODE_WORLD_READABLE) | must | MEDIUM+ (storage-file-mode) | **DETECTED** | MEDIUM |  |
| 31 | token written to the log | must | LOW+ (log-sensitive-strings/log-credential-object) | **DETECTED** | MEDIUM |  |
| 32 | exported activity: zip entry name used as a file name (Zip Slip) | must | HIGH+ (zip-slip/taint-flow) | **DETECTED** | HIGH |  |
| 33 | exported activity: path from the Intent data deleted | must | HIGH+ (taint-flow) | **DETECTED** | HIGH |  |
| 34 | code loaded from an external-storage directory (DexClassLoader) | must | HIGH+ (dex-load-writable-dir/dynamic-code-loading) | **DETECTED** | HIGH |  |
| 36 | exported service: ObjectInputStream.readObject on bytes from an Intent extra | must | HIGH+ (deserialization/taint-flow) | **DETECTED** | HIGH |  |
| 40 | Cipher algorithm string built at run time ("AES/" + "ECB/PKCS5Padding") | probe | HIGH+ (crypto-cipher) | **MISSED** | - |  |
| 41 | key hidden as Base64.decode("...") and used in SecretKeySpec | probe | HIGH+ (crypto-hardcoded-key) | **DETECTED** | HIGH |  |
| 42 | key bytes in a static array field, used by SecretKeySpec in another method | probe | HIGH+ (crypto-hardcoded-key) | **DETECTED** | HIGH |  |
| 43 | exported activity forwards its extra to a NOT exported activity that loads it in a WebView | probe | HIGH+ (taint-flow/webview-intent-url) | **DETECTED** | HIGH |  |
| 44 | deep link: a query parameter of the Intent data loaded into a WebView | probe | HIGH+ (taint-flow/webview-intent-url) | **DETECTED** | HIGH |  |
| 45 | exported service: extra passed to Runtime.exec(String[]) as the sh -c argument | probe | CRITICAL+ (taint-flow/shell-exec) | **DETECTED** | CRITICAL |  |
| 46 | exported activity: extra formatted into a rawQuery with String.format | probe | HIGH+ (taint-flow/sql-concat) | **DETECTED** | HIGH | MEDIUM Possible SQL built from UI input ( |
| 47 | exported provider: openFile builds a path from the last path segment | probe | HIGH+ (provider-openfile-segment/taint-flow) | **DETECTED** | HIGH |  |
| 50 | vendor token in a string constant (1password-secret-key) | must | HIGH+ (secrets-vendor-tokens/secrets-known-formats) | **DETECTED** | HIGH |  |
| 51 | vendor token in a string constant (anthropic-api-key) | must | HIGH+ (secrets-vendor-tokens/secrets-known-formats) | **DETECTED** | HIGH | HIGH Anthropic API key embedded |
| 52 | vendor token in a string constant (huggingface-organization-api-token) | must | HIGH+ (secrets-vendor-tokens/secrets-known-formats) | **DETECTED** | HIGH |  |
| 53 | vendor token in a string constant (intra42-client-secret) | must | HIGH+ (secrets-vendor-tokens/secrets-known-formats) | **DETECTED** | HIGH |  |
| 54 | vendor token in a string constant (notion-api-token) | must | HIGH+ (secrets-vendor-tokens/secrets-known-formats) | **DETECTED** | HIGH |  |
| 55 | vendor token in a string constant (sourcegraph-access-token) | must | HIGH+ (secrets-vendor-tokens/secrets-known-formats) | **DETECTED** | HIGH |  |
| 56 | vendor token in a string constant (stripe-access-token) | must | HIGH+ (secrets-vendor-tokens/secrets-known-formats) | **DETECTED** | HIGH |  |
| 60 | Jackson enableDefaultTyping in app code | must | MEDIUM+ (jackson-default-typing) | **DETECTED** | MEDIUM |  |
| 61 | @JsonTypeInfo(use = CLASS) on an app model | must | MEDIUM+ (jackson-default-typing) | **DETECTED** | MEDIUM |  |
| 62 | SQLCipher passphrase is a string constant | must | HIGH+ (crypto-db-passphrase) | **DETECTED** | HIGH |  |
| 63 | SQLCipher passphrase from ANDROID_ID | must | MEDIUM+ (crypto-db-passphrase) | **DETECTED** | MEDIUM |  |

must-cases (43): rule fired for 43 (at the expected severity or higher for 43, LOWER for 0), MISSED 0
probes (10): 03=DETECTED/HIGH, 13=DETECTED/CRITICAL, 40=MISSED/-, 41=DETECTED/HIGH, 42=DETECTED/HIGH, 43=DETECTED/HIGH, 44=DETECTED/HIGH, 45=DETECTED/CRITICAL, 46=DETECTED/HIGH, 47=DETECTED/HIGH
