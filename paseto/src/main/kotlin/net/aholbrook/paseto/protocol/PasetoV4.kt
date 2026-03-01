@file:Suppress("MagicNumber")

package net.aholbrook.paseto.protocol

import net.aholbrook.paseto.UrlSafeNoPadding
import net.aholbrook.paseto.crypto.ED25519_BYTES
import net.aholbrook.paseto.crypto.blake2b
import net.aholbrook.paseto.crypto.chaCha20
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.crypto.ed25519Sign
import net.aholbrook.paseto.crypto.ed25519Verify
import net.aholbrook.paseto.crypto.generateNonce
import net.aholbrook.paseto.crypto.pae
import net.aholbrook.paseto.decodeOrNull
import net.aholbrook.paseto.exception.DecryptionException
import net.aholbrook.paseto.exception.EncryptionException
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.SignatureVerificationException
import net.aholbrook.paseto.exception.SigningException
import java.util.Arrays
import kotlin.io.encoding.Base64

private const val VERSION = "v4"
private const val HEADER_LOCAL: String = VERSION + SEPARATOR + PURPOSE_LOCAL + SEPARATOR // v4.local.
private const val HEADER_PUBLIC: String = VERSION + SEPARATOR + PURPOSE_PUBLIC + SEPARATOR // v4.public.

private fun concat(a: ByteArray, b: ByteArray): ByteArray {
    val result = ByteArray(a.size + b.size)
    System.arraycopy(a, 0, result, 0, a.size)
    System.arraycopy(b, 0, result, a.size, b.size)
    return result
}

object PasetoV4 : Paseto {
    override val version: Version = Version.V4
    override val supportsImplicitAssertion: Boolean = true

    override fun encrypt(payload: String, key: SymmetricKey, footer: String?, implicitAssertion: String?): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            // Verify key version.
            val keyMaterial = key.getKeyMaterialFor(Version.V4, Purpose.LOCAL)
            val payloadBytes = payload.toByteArray(Charsets.UTF_8)
            val footerBytes = (footer ?: "").toByteArray(Charsets.UTF_8)
            val implicitAssertionBytes = (implicitAssertion ?: "").toByteArray(Charsets.UTF_8)

            val n = generateNonce(32)
            val tmp = ByteArray(56)
            cleanup.add { tmp.fill(0) }
            blake2b(tmp, keyMaterial, concat("paseto-encryption-key".toByteArray(Charsets.UTF_8), n))
            val ek = Arrays.copyOfRange(tmp, 0, 32)
            cleanup.add { ek.fill(0) }
            val n2 = Arrays.copyOfRange(tmp, 32, 56)
            cleanup.add { n2.fill(0) }
            val ak = ByteArray(32)
            cleanup.add { ak.fill(0) }
            blake2b(ak, keyMaterial, "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8), n)
            val c = ByteArray(payloadBytes.size)
            if (!chaCha20(c, payloadBytes, n2, ek)) {
                throw EncryptionException()
            }
            val preAuth = pae(HEADER_LOCAL.toByteArray(Charsets.UTF_8), n, c, footerBytes, implicitAssertionBytes)
            val t = ByteArray(32)
            blake2b(t, ak, preAuth)

            val nct = ByteArray(n.size + c.size + t.size)
            System.arraycopy(n, 0, nct, 0, n.size)
            System.arraycopy(c, 0, nct, n.size, c.size)
            System.arraycopy(t, 0, nct, n.size + c.size, t.size)

            return if (footerBytes.isNotEmpty()) {
                HEADER_LOCAL + Base64.UrlSafeNoPadding.encode(nct) + SEPARATOR +
                    Base64.UrlSafeNoPadding.encode(footerBytes)
            } else {
                HEADER_LOCAL + Base64.UrlSafeNoPadding.encode(nct)
            }
        } finally {
            key.clear()
            cleanup.forEach { it.run() }
        }
    }

    override fun decrypt(token: String, key: SymmetricKey, footer: String?, implicitAssertion: String?): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            // Verify key version.
            val keyMaterial = key.getKeyMaterialFor(Version.V4, Purpose.LOCAL)

            // Split token into sections
            val sections = split(token)

            // Check header
            checkHeader(token, sections, HEADER_LOCAL)

            // Decode footer
            val decodedFooter = decodeFooter(token, sections, footer)
            val footerBytes = decodedFooter.toByteArray(Charsets.UTF_8)

            val implicitAssertionBytes = (implicitAssertion ?: "").toByteArray(Charsets.UTF_8)

            // Decrypt
            val nct = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
                ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
            val n = Arrays.copyOfRange(nct, 0, 32)
            val t = Arrays.copyOfRange(nct, nct.size - 32, nct.size)
            val c = Arrays.copyOfRange(nct, n.size, nct.size - t.size)

            val tmp = ByteArray(56)
            cleanup.add { tmp.fill(0) }
            blake2b(tmp, keyMaterial, "paseto-encryption-key".toByteArray(Charsets.UTF_8), n)
            val ek = Arrays.copyOfRange(tmp, 0, 32)
            cleanup.add { ek.fill(0) }
            val n2 = Arrays.copyOfRange(tmp, 32, 56)
            cleanup.add { n2.fill(0) }
            val ak = ByteArray(32)
            cleanup.add { ak.fill(0) }
            blake2b(ak, keyMaterial, "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8), n)
            val preAuth = pae(HEADER_LOCAL.toByteArray(Charsets.UTF_8), n, c, footerBytes, implicitAssertionBytes)
            val t2 = ByteArray(32)
            blake2b(t2, ak, preAuth)
            if (!t.constantTimeEquals(t2)) {
                throw DecryptionException(token)
            }
            val p = ByteArray(c.size)
            if (!chaCha20(p, c, n2, ek)) {
                throw DecryptionException(token)
            }

            return p.toString(Charsets.UTF_8)
        } finally {
            key.clear()
            cleanup.forEach { it.run() }
        }
    }

    override fun sign(
        payload: String,
        secretKey: AsymmetricSecretKey,
        footer: String?,
        implicitAssertion: String?,
    ): String {
        try {
            // Verify key version.
            val keyMaterial = secretKey.getKeyMaterialFor(Version.V4, Purpose.PUBLIC)
            val payloadBytes = payload.toByteArray(Charsets.UTF_8)
            val footerBytes = (footer ?: "").toByteArray(Charsets.UTF_8)

            val m2 = pae(
                HEADER_PUBLIC.toByteArray(Charsets.UTF_8),
                payloadBytes,
                footerBytes,
                (implicitAssertion ?: "").toByteArray(Charsets.UTF_8),
            )
            val sig = ByteArray(ED25519_BYTES)
            if (!ed25519Sign(sig, m2, keyMaterial)) {
                throw SigningException(payload)
            }

            val msig = ByteArray(payloadBytes.size + sig.size)
            System.arraycopy(payloadBytes, 0, msig, 0, payloadBytes.size)
            System.arraycopy(sig, 0, msig, payloadBytes.size, sig.size)

            return if (footerBytes.isNotEmpty()) {
                HEADER_PUBLIC + Base64.UrlSafeNoPadding.encode(msig) + SEPARATOR +
                    Base64.UrlSafeNoPadding.encode(footerBytes)
            } else {
                HEADER_PUBLIC + Base64.UrlSafeNoPadding.encode(msig)
            }
        } finally {
            secretKey.clear()
        }
    }

    override fun verify(
        token: String,
        publicKey: AsymmetricPublicKey,
        footer: String?,
        implicitAssertion: String?,
    ): String {
        // Verify key version.
        val keyMaterial = publicKey.getKeyMaterialFor(Version.V4, Purpose.PUBLIC)

        // Split token into sections
        val sections = split(token)

        // Check header
        checkHeader(token, sections, HEADER_PUBLIC)

        // Decode footer
        val decodedFooter = decodeFooter(token, sections, footer)

        // Verify
        val msig = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
            ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)

        val s = ByteArray(ED25519_BYTES)
        // verify length
        if (msig.size < s.size + 1) {
            throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                minLength = s.size + 1
            }
        }
        val m = ByteArray(msig.size - s.size)
        System.arraycopy(msig, msig.size - s.size, s, 0, s.size)
        System.arraycopy(msig, 0, m, 0, m.size)

        val m2 = pae(
            HEADER_PUBLIC.toByteArray(Charsets.UTF_8),
            m,
            decodedFooter.toByteArray(Charsets.UTF_8),
            (implicitAssertion ?: "").toByteArray(Charsets.UTF_8),
        )
        if (!ed25519Verify(s, m2, keyMaterial)) {
            throw SignatureVerificationException(token)
        }

        // Convert from JSON
        return m.toString(Charsets.UTF_8)
    }
}
