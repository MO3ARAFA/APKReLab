package dev.apkrelab

import android.content.Context
import android.util.Base64
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Signing key stored as a PKCS12 file in the app's private storage (files/signing.p12).
 * Its password is random and kept encrypted with the Android Keystore (SecureStore).
 * Unlike the old non-exportable Keystore key, it can be exported (with a user password) and imported again,
 * so the same key survives reinstalling APK ReLab. The self-signed X.509 certificate is built by hand (DER), no extra library.
 */
object SigningKey {
    private const val ALIAS = "relab"
    private lateinit var ctx: Context

    fun init(c: Context) { ctx = c.applicationContext }

    private val p12: File get() = File(ctx.filesDir, "signing.p12")
    private fun prefs() = ctx.getSharedPreferences("apkrelab_prefs", Context.MODE_PRIVATE)

    private fun internalPwd(): CharArray {
        prefs().getString("kp", null)?.let { SecureStore.decrypt(it) }?.let { return it.toCharArray() }
        if (p12.exists()) throw BuildError("Signing key file exists but its password is unreadable. Use 'New key' (or import your backup).")
        val b = ByteArray(24)
        SecureRandom().nextBytes(b)
        val pw = Base64.encodeToString(b, Base64.NO_WRAP)
        prefs().edit().putString("kp", SecureStore.encrypt(pw)).apply()
        return pw.toCharArray()
    }

    fun exists(): Boolean = p12.exists()

    fun load(): Pair<java.security.PrivateKey, X509Certificate> {
        if (!p12.exists()) createNew()
        return readP12(p12.inputStream(), internalPwd())
    }

    fun createNew() {
        p12.delete()
        prefs().edit().remove("kp").apply()
        val gen = KeyPairGenerator.getInstance("RSA")
        gen.initialize(2048)
        val kp = gen.generateKeyPair()
        val cert = selfSign(kp)
        val pw = internalPwd()   // must be created BEFORE the file exists (internalPwd refuses a file without a password)
        writeP12File(kp.private, cert, pw)
    }

    fun reset() {
        p12.delete()
        prefs().edit().remove("kp").apply()
    }

    fun exportTo(out: OutputStream, pw: CharArray) {
        val (pk, cert) = load()
        writeP12(out, pk, cert, pw)
    }

    fun importFrom(input: InputStream, pw: CharArray) {
        val (pk, cert) = readP12(input, pw)
        p12.delete()
        prefs().edit().remove("kp").apply()
        val internal = internalPwd()   // before the file exists
        writeP12File(pk, cert, internal)
    }

    fun fingerprint(): String? {
        if (!exists()) return null
        return try {
            MessageDigest.getInstance("SHA-256").digest(load().second.encoded)
                .joinToString(":") { String.format("%02X", it) }
        } catch (_: Throwable) { null }
    }

    // ---------------------------------------------------------------- PKCS12

    private fun readP12(input: InputStream, pw: CharArray): Pair<java.security.PrivateKey, X509Certificate> {
        val ks = KeyStore.getInstance("PKCS12")
        input.use { ks.load(it, pw) }
        val alias = Collections.list(ks.aliases()).firstOrNull { ks.isKeyEntry(it) }
            ?: throw BuildError("No private key found in that file")
        val pk = ks.getKey(alias, pw) as PrivateKey
        val cert = ks.getCertificate(alias) as X509Certificate
        return pk to cert
    }

    /** 0.12.4: write to a temp file, then rename, so a failed write never leaves an empty/corrupt signing.p12. */
    private fun writeP12File(pk: PrivateKey, cert: X509Certificate, pw: CharArray) {
        val tmp = File(ctx.filesDir, "signing.p12.tmp")
        try {
            writeP12(tmp.outputStream(), pk, cert, pw)
            if (!tmp.renameTo(p12)) throw BuildError("Could not save the signing key file")
        } finally {
            tmp.delete()
        }
    }

    private fun writeP12(out: OutputStream, pk: PrivateKey, cert: X509Certificate, pw: CharArray) {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry(ALIAS, pk, pw, arrayOf(cert))
        out.use { ks.store(it, pw) }
    }

    // ---------------------------------------------------------------- minimal DER / self-signed certificate

    private fun tlv(tag: Int, v: ByteArray): ByteArray {
        val n = v.size
        val len = when {
            n < 128 -> byteArrayOf(n.toByte())
            n < 256 -> byteArrayOf(0x81.toByte(), n.toByte())
            else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        }
        return byteArrayOf(tag.toByte()) + len + v
    }

    private fun seq(vararg parts: ByteArray): ByteArray = tlv(0x30, parts.fold(ByteArray(0)) { a, b -> a + b })

    private fun selfSign(kp: KeyPair): X509Certificate {
        val sigAlg = seq(
            tlv(0x06, byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B)),
            tlv(0x05, ByteArray(0))
        )
        val name = seq(tlv(0x31, seq(tlv(0x06, byteArrayOf(0x55, 0x04, 0x03)), tlv(0x0C, "APK ReLab".toByteArray(Charsets.UTF_8)))))
        val utc = TimeZone.getTimeZone("UTC")
        val fmtU = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US).apply { timeZone = utc }
        val fmtG = SimpleDateFormat("yyyyMMddHHmmss'Z'", Locale.US).apply { timeZone = utc }
        val from = Date(System.currentTimeMillis() - 24L * 3600 * 1000)
        val to = Date(System.currentTimeMillis() + 30L * 365 * 24 * 3600 * 1000)
        val validity = seq(tlv(0x17, fmtU.format(from).toByteArray()), tlv(0x18, fmtG.format(to).toByteArray()))
        val tbs = seq(
            tlv(0xA0, tlv(0x02, byteArrayOf(2))),
            tlv(0x02, BigInteger.valueOf(System.currentTimeMillis()).toByteArray()),
            sigAlg, name, validity, name,
            kp.public.encoded
        )
        val sig = Signature.getInstance("SHA256withRSA").apply {
            initSign(kp.private)
            update(tbs)
        }.sign()
        val der = seq(tbs, sigAlg, tlv(0x03, byteArrayOf(0) + sig))
        return CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }
}
