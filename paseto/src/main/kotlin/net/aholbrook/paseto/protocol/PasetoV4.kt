@file:Suppress("MagicNumber", "DuplicatedCode")

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
import net.aholbrook.paseto.exception.InvalidHeaderException
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.SignatureVerificationException
import net.aholbrook.paseto.exception.SigningException
import kotlin.io.encoding.Base64

internal object PasetoV4 : Paseto {
    override val version: Version = Version.V4
    override val supportsImplicitAssertion: Boolean = true

    override fun encrypt(m: ByteArray, key: SymmetricKey, footer: String, implicitAssertion: String): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            // Verify key version.
            val k = key.getKeyMaterialFor(Version.V4, Purpose.LOCAL)
            val h = "v4.local."
            val f = footer.toByteArray(Charsets.UTF_8)
            val i = implicitAssertion.toByteArray(Charsets.UTF_8)
            val n = generateNonce(32)

            val tmp = ByteArray(56)
            cleanup.add { tmp.fill(0) }
            blake2b(tmp, k, "paseto-encryption-key".toByteArray(Charsets.UTF_8) + n)
            val ek = tmp.copyOfRange(0, 32)
            cleanup.add { ek.fill(0) }
            val n2 = tmp.copyOfRange(32, 56)
            cleanup.add { n2.fill(0) }
            val ak = ByteArray(32)
            cleanup.add { ak.fill(0) }
            blake2b(ak, k, "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8), n)
            val c = ByteArray(m.size)
            if (!chaCha20(c, m, n2, ek)) {
                throw EncryptionException()
            }
            val preAuth = pae(h.toByteArray(Charsets.UTF_8), n, c, f, i)
            val t = ByteArray(32)
            blake2b(t, ak, preAuth)

            return h + Base64.UrlSafeNoPadding.encode(n + c + t) +
                if (f.isEmpty()) {
                    ""
                } else {
                    ".${Base64.UrlSafeNoPadding.encode(f)}"
                }
        } finally {
            key.clear()
            cleanup.forEach { it.run() }
        }
    }

    override fun decrypt(
        token: String,
        key: SymmetricKey,
        footer: String,
        implicitAssertion: String,
    ): Pair<String, String> {
        val cleanup = mutableListOf<Runnable>()

        try {
            val k = key.getKeyMaterialFor(Version.V4, Purpose.LOCAL)
            val h = "v4.local."
            val sections = split(token)
            val f = decodeFooter(token, sections, footer)
            val i = implicitAssertion.toByteArray(Charsets.UTF_8)

            // Check header
            if (!token.startsWith(h)) {
                throw InvalidHeaderException(sections.version + SEPARATOR + sections.purpose + SEPARATOR, h, token)
            }

            // Decrypt
            val nct = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
                ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
            if (nct.size < 64 + 1) {
                throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                    minLength = 64 + 1
                }
            }
            val n = nct.copyOfRange(0, 32)
            val t = nct.copyOfRange(nct.size - 32, nct.size)
            val c = nct.copyOfRange(32, nct.size - 32)

            val tmp = ByteArray(56)
            cleanup.add { tmp.fill(0) }
            blake2b(tmp, k, "paseto-encryption-key".toByteArray(Charsets.UTF_8), n)
            val ek = tmp.copyOfRange(0, 32)
            cleanup.add { ek.fill(0) }
            val n2 = tmp.copyOfRange(32, 56)
            cleanup.add { n2.fill(0) }
            val ak = ByteArray(32)
            cleanup.add { ak.fill(0) }
            blake2b(ak, k, "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8), n)
            val preAuth = pae(h.toByteArray(Charsets.UTF_8), n, c, f.toByteArray(Charsets.UTF_8), i)
            val t2 = ByteArray(32)
            blake2b(t2, ak, preAuth)
            if (!t.constantTimeEquals(t2)) {
                throw DecryptionException(token)
            }
            val p = ByteArray(c.size)
            if (!chaCha20(p, c, n2, ek)) {
                throw DecryptionException(token)
            }

            return Pair(p.toString(Charsets.UTF_8), f)
        } finally {
            key.clear()
            cleanup.forEach { it.run() }
        }
    }

    override fun sign(
        m: ByteArray,
        secretKey: AsymmetricSecretKey,
        footer: String,
        implicitAssertion: String,
    ): String {
        try {
            val k = secretKey.getKeyMaterialFor(Version.V4, Purpose.PUBLIC)
            val h = "v4.public."
            val f = footer.toByteArray(Charsets.UTF_8)
            val i = implicitAssertion.toByteArray(Charsets.UTF_8)

            val m2 = pae(h.toByteArray(Charsets.UTF_8), m, f, i)
            val sig = ByteArray(ED25519_BYTES)
            if (!ed25519Sign(sig, m2, k)) {
                throw SigningException(m)
            }

            return h + Base64.UrlSafeNoPadding.encode(m + sig) +
                if (f.isEmpty()) {
                    ""
                } else {
                    ".${Base64.UrlSafeNoPadding.encode(f)}"
                }
        } finally {
            secretKey.clear()
        }
    }

    override fun verify(
        token: String,
        publicKey: AsymmetricPublicKey,
        footer: String,
        implicitAssertion: String,
    ): Pair<String, String> {
        val pk = publicKey.getKeyMaterialFor(Version.V4, Purpose.PUBLIC)
        val h = "v4.public."
        val sections = split(token)
        val f = decodeFooter(token, sections, footer)
        val i = implicitAssertion.toByteArray(Charsets.UTF_8)

        // Check header
        if (!token.startsWith(h)) {
            throw InvalidHeaderException(sections.version + SEPARATOR + sections.purpose + SEPARATOR, h, token)
        }

        // Verify
        val sm = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
            ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
        if (sm.size < ED25519_BYTES + 1) {
            throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                minLength = ED25519_BYTES + 1
            }
        }
        val s = sm.copyOfRange(sm.size - ED25519_BYTES, sm.size)
        val m = sm.copyOfRange(0, sm.size - s.size)

        val m2 = pae(h.toByteArray(Charsets.UTF_8), m, f.toByteArray(Charsets.UTF_8), i)
        if (!ed25519Verify(s, m2, pk)) {
            throw SignatureVerificationException(token)
        }

        // Convert from JSON
        return Pair(m.toString(Charsets.UTF_8), f)
    }
}
