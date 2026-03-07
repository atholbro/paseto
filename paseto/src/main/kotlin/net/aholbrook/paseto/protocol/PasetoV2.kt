@file:Suppress("MagicNumber")

package net.aholbrook.paseto.protocol

import net.aholbrook.paseto.UrlSafeNoPadding
import net.aholbrook.paseto.crypto.ED25519_BYTES
import net.aholbrook.paseto.crypto.XCHACHA20_POLY1305_IETF_ABYTES
import net.aholbrook.paseto.crypto.XCHACHA20_POLY1305_IETF_NPUBBYTES
import net.aholbrook.paseto.crypto.aeadXChaCha20Poly1305IetfDecrypt
import net.aholbrook.paseto.crypto.aeadXChaCha20Poly1305IetfEncrypt
import net.aholbrook.paseto.crypto.blake2b
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
import net.aholbrook.paseto.protocol.key.AsymmetricPublicKey
import net.aholbrook.paseto.protocol.key.AsymmetricSecretKey
import net.aholbrook.paseto.protocol.key.SymmetricKey
import kotlin.io.encoding.Base64

internal object PasetoV2 : Paseto {
    override val version: Version = Version.V2
    override val supportsImplicitAssertion: Boolean = false

    override fun encrypt(m: ByteArray, key: SymmetricKey, footer: String, implicitAssertion: String): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            val k = key.getKeyMaterialFor(Version.V2, Purpose.LOCAL)
            val h = "v2.local."
            val f = footer.toByteArray(Charsets.UTF_8)
            val b: ByteArray = generateNonce(24)
            cleanup.add { b.fill(0) }
            val n = ByteArray(XCHACHA20_POLY1305_IETF_NPUBBYTES)
            blake2b(n, b, m)

            val preAuth = pae(h.toByteArray(Charsets.UTF_8), n, f)
            val c = ByteArray(m.size + XCHACHA20_POLY1305_IETF_ABYTES)
            if (!aeadXChaCha20Poly1305IetfEncrypt(c, m, preAuth, n, k)) {
                throw EncryptionException()
            }

            return h + Base64.UrlSafeNoPadding.encode(n + c) +
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
        footer: String?,
        implicitAssertion: String,
    ): Pair<String, String> {
        try {
            val k = key.getKeyMaterialFor(Version.V2, Purpose.LOCAL)
            val h = "v2.local."
            val sections = split(token)
            val f = decodeFooter(token, sections, footer)

            // Check header
            if (!token.startsWith(h)) {
                throw InvalidHeaderException(sections.version + SEPARATOR + sections.purpose + SEPARATOR, h, token)
            }

            // Decrypt
            val nc = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
                ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
            // verify length
            if (nc.size < XCHACHA20_POLY1305_IETF_NPUBBYTES + 1) {
                throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                    minLength = XCHACHA20_POLY1305_IETF_NPUBBYTES + 1
                }
            }
            val n = nc.copyOfRange(0, XCHACHA20_POLY1305_IETF_NPUBBYTES)
            val c = nc.copyOfRange(XCHACHA20_POLY1305_IETF_NPUBBYTES, nc.size)

            val preAuth = pae(h.toByteArray(Charsets.UTF_8), n, f.toByteArray(Charsets.UTF_8))
            val p = ByteArray(c.size - XCHACHA20_POLY1305_IETF_ABYTES)
            if (!aeadXChaCha20Poly1305IetfDecrypt(p, c, preAuth, n, k)) {
                throw DecryptionException(token)
            }

            // Convert from JSON
            return Pair(p.toString(Charsets.UTF_8), f)
        } finally {
            key.clear()
        }
    }

    override fun sign(
        m: ByteArray,
        secretKey: AsymmetricSecretKey,
        footer: String,
        implicitAssertion: String,
    ): String {
        try {
            // Verify key version.
            val k = secretKey.getKeyMaterialFor(Version.V2, Purpose.PUBLIC)
            val h = "v2.public."
            val f = footer.toByteArray(Charsets.UTF_8)

            val m2 = pae(h.toByteArray(Charsets.UTF_8), m, f)
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
        footer: String?,
        implicitAssertion: String,
    ): Pair<String, String> {
        val k = publicKey.getKeyMaterialFor(Version.V2, Purpose.PUBLIC)
        val h = "v2.public."
        val sections = split(token)
        val f = decodeFooter(token, sections, footer)

        // Check header
        if (!token.startsWith(h)) {
            throw InvalidHeaderException(sections.version + SEPARATOR + sections.purpose + SEPARATOR, h, token)
        }

        // Verify
        val sm = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
            ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
        // verify length
        if (sm.size < ED25519_BYTES + 1) {
            throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                minLength = ED25519_BYTES + 1
            }
        }
        val s = sm.copyOfRange(sm.size - ED25519_BYTES, sm.size)
        val m = sm.copyOfRange(0, sm.size - ED25519_BYTES)

        val m2 = pae(h.toByteArray(Charsets.UTF_8), m, f.toByteArray(Charsets.UTF_8))
        if (!ed25519Verify(s, m2, k)) {
            throw SignatureVerificationException(token)
        }

        // Convert from JSON
        return Pair(m.toString(Charsets.UTF_8), f)
    }
}
