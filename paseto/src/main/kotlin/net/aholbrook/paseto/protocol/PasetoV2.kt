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
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.SignatureVerificationException
import net.aholbrook.paseto.exception.SigningException
import kotlin.io.encoding.Base64

private const val VERSION = "v2"
private const val HEADER_LOCAL: String = VERSION + SEPARATOR + PURPOSE_LOCAL + SEPARATOR // v2.local.
private const val HEADER_PUBLIC: String = VERSION + SEPARATOR + PURPOSE_PUBLIC + SEPARATOR // v2.public.
private const val NONCE_SIZE = 24

object PasetoV2 : Paseto {
    override val version: Version = Version.V2
    override val supportsImplicitAssertion: Boolean = false

    override fun encrypt(payload: String, key: SymmetricKey, footer: String?, implicitAssertion: String?): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            // Verify key version.
            val keyMaterial = key.getKeyMaterialFor(Version.V2, Purpose.LOCAL)

            val payloadBytes = payload.toByteArray(Charsets.UTF_8)
            val footerBytes = (footer ?: "").toByteArray(Charsets.UTF_8)

            val nonce: ByteArray = generateNonce(NONCE_SIZE)
            cleanup.add { nonce.fill(0) }
            val n = ByteArray(XCHACHA20_POLY1305_IETF_NPUBBYTES)
            blake2b(n, nonce, payloadBytes)

            val preAuth = pae(HEADER_LOCAL.toByteArray(Charsets.UTF_8), n, footerBytes)

            val c = ByteArray(payloadBytes.size + XCHACHA20_POLY1305_IETF_ABYTES)
            if (!aeadXChaCha20Poly1305IetfEncrypt(c, payloadBytes, preAuth, n, keyMaterial)) {
                throw EncryptionException()
            }

            val nc = ByteArray(n.size + c.size)
            System.arraycopy(n, 0, nc, 0, n.size)
            System.arraycopy(c, 0, nc, n.size, c.size)

            return if (footerBytes.isNotEmpty()) {
                HEADER_LOCAL + Base64.UrlSafeNoPadding.encode(nc) + SEPARATOR +
                    Base64.UrlSafeNoPadding.encode(footerBytes)
            } else {
                HEADER_LOCAL + Base64.UrlSafeNoPadding.encode(nc)
            }
        } finally {
            key.clear()
            cleanup.forEach { it.run() }
        }
    }

    override fun decrypt(token: String, key: SymmetricKey, footer: String?, implicitAssertion: String?): String {
        try {
            // Verify key version.
            val keyMaterial = key.getKeyMaterialFor(Version.V2, Purpose.LOCAL)

            // Split token into sections
            val sections = split(token)

            // Check header
            checkHeader(token, sections, HEADER_LOCAL)

            // Decode footer
            val decodedFooter = decodeFooter(token, sections, footer)

            // Decrypt
            val nc = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
                ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
            val n = ByteArray(XCHACHA20_POLY1305_IETF_NPUBBYTES)
            // verify length
            if (nc.size < n.size + 1) {
                throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                    minLength = n.size + 1
                }
            }
            val c = ByteArray(nc.size - n.size)
            System.arraycopy(nc, 0, n, 0, n.size)
            System.arraycopy(nc, n.size, c, 0, c.size)

            val preAuth = pae(HEADER_LOCAL.toByteArray(Charsets.UTF_8), n, decodedFooter.toByteArray(Charsets.UTF_8))
            val p = ByteArray(c.size - XCHACHA20_POLY1305_IETF_ABYTES)
            if (!aeadXChaCha20Poly1305IetfDecrypt(p, c, preAuth, n, keyMaterial)) {
                throw DecryptionException(token)
            }

            // Convert from JSON
            return p.toString(Charsets.UTF_8)
        } finally {
            key.clear()
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
            val keyMaterial = secretKey.getKeyMaterialFor(Version.V2, Purpose.PUBLIC)

            val payloadBytes = payload.toByteArray(Charsets.UTF_8)
            val footerBytes = (footer ?: "").toByteArray(Charsets.UTF_8)

            val m2 = pae(HEADER_PUBLIC.toByteArray(Charsets.UTF_8), payloadBytes, footerBytes)
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
        val keyMaterial = publicKey.getKeyMaterialFor(Version.V2, Purpose.PUBLIC)

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

        val m2 = pae(HEADER_PUBLIC.toByteArray(Charsets.UTF_8), m, decodedFooter.toByteArray(Charsets.UTF_8))
        if (!ed25519Verify(s, m2, keyMaterial)) {
            throw SignatureVerificationException(token)
        }

        // Convert from JSON
        return m.toString(Charsets.UTF_8)
    }
}
