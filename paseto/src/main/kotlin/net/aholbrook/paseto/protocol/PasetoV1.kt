package net.aholbrook.paseto.protocol

import net.aholbrook.paseto.UrlSafeNoPadding
import net.aholbrook.paseto.crypto.HKDF_SALT_LEN
import net.aholbrook.paseto.crypto.RSA_SIGNATURE_LEN
import net.aholbrook.paseto.crypto.SHA384_OUT_LEN
import net.aholbrook.paseto.crypto.aes256CtrDecrypt
import net.aholbrook.paseto.crypto.aes256CtrEncrypt
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.crypto.generateNonce
import net.aholbrook.paseto.crypto.hkdfExtractAndExpand
import net.aholbrook.paseto.crypto.hmacSha384
import net.aholbrook.paseto.crypto.pae
import net.aholbrook.paseto.crypto.rsaSign
import net.aholbrook.paseto.crypto.rsaVerify
import net.aholbrook.paseto.decodeOrNull
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.SignatureVerificationException
import java.security.PublicKey
import kotlin.io.encoding.Base64

private const val VERSION = "v1"
private const val HEADER_LOCAL: String = VERSION + SEPARATOR + PURPOSE_LOCAL + SEPARATOR // v1.local.
private const val HEADER_PUBLIC: String = VERSION + SEPARATOR + PURPOSE_PUBLIC + SEPARATOR // v1.public.
private const val NONCE_SIZE = 32
private val HKDF_INFO_EK: ByteArray = "paseto-encryption-key".toByteArray(Charsets.UTF_8)
private val HKDF_INFO_AK: ByteArray = "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8)

object PasetoV1 : Paseto {
    override val version: Version = Version.V1
    override val supportsImplicitAssertion: Boolean = false

    override fun encrypt(
        payload: String,
        key: SymmetricKey,
        footer: String?,
        implicitAssertion: String?
    ): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            // Verify key version.
            val keyMaterial = key.getKeyMaterialFor(Version.V1, Purpose.LOCAL)

            val payloadBytes = payload.toByteArray(Charsets.UTF_8)
            val footerBytes = (footer ?: "").toByteArray(Charsets.UTF_8)

            // Generate n
            val random = generateNonce(NONCE_SIZE)
            cleanup.add { random.fill(0) }
            val n = ByteArray(NONCE_SIZE)
            System.arraycopy(hmacSha384(payloadBytes, random), 0, n, 0, n.size)

            // Split N into salt/nonce
            val salt = ByteArray(HKDF_SALT_LEN)
            val nonce = ByteArray(HKDF_SALT_LEN)
            System.arraycopy(n, 0, salt, 0, salt.size)
            System.arraycopy(n, salt.size, nonce, 0, nonce.size)

            // Create ek/ak for AEAD
            val ek = hkdfExtractAndExpand(salt, keyMaterial, HKDF_INFO_EK)
            cleanup.add { ek.fill(0) }
            val ak = hkdfExtractAndExpand(salt, keyMaterial, HKDF_INFO_AK)
            cleanup.add { ak.fill(0) }

            val c = aes256CtrEncrypt(payloadBytes, ek, nonce)
            val preAuth = pae(HEADER_LOCAL.toByteArray(Charsets.UTF_8), n, c, footerBytes)
            val t = hmacSha384(preAuth, ak)

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

    override fun decrypt(
        token: String,
        key: SymmetricKey,
        footer: String?,
        implicitAssertion: String?
    ): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            // Verify key version.
            val keyMaterial = key.getKeyMaterialFor(Version.V1, Purpose.LOCAL)

            // Split token into sections
            val sections = split(token)

            // Check header
            checkHeader(token, sections, HEADER_LOCAL)

            // Decode footer
            val decodedFooter = decodeFooter(token, sections, footer)

            // Decrypt
            val nct = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
                ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
            val n = ByteArray(NONCE_SIZE)
            val t = ByteArray(SHA384_OUT_LEN)
            // verify length
            if (nct.size < n.size + t.size + 1) {
                throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                    minLength = n.size + t.size + 1
                }
            }
            val c = ByteArray(nct.size - n.size - t.size)
            System.arraycopy(nct, 0, n, 0, n.size)
            System.arraycopy(nct, n.size, c, 0, c.size)
            System.arraycopy(nct, n.size + c.size, t, 0, t.size)

            // Split N into salt/nonce
            val salt = ByteArray(HKDF_SALT_LEN)
            val nonce = ByteArray(HKDF_SALT_LEN)
            System.arraycopy(n, 0, salt, 0, salt.size)
            System.arraycopy(n, salt.size, nonce, 0, nonce.size)

            // Create ek/ak for AEAD
            val ek = hkdfExtractAndExpand(salt, keyMaterial, HKDF_INFO_EK)
            cleanup.add { ek.fill(0) }
            val ak = hkdfExtractAndExpand(salt, keyMaterial, HKDF_INFO_AK)
            cleanup.add { ak.fill(0) }

            val preAuth = pae(
                HEADER_LOCAL.toByteArray(Charsets.UTF_8),
                n,
                c,
                decodedFooter.toByteArray(Charsets.UTF_8)
            )
            val t2 = hmacSha384(preAuth, ak)
            if (!t.constantTimeEquals(t2)) {
                throw SignatureVerificationException(token)
            }

            val m = aes256CtrDecrypt(c, ek, nonce)

            return m.toString(Charsets.UTF_8)
        } finally {
            key.clear()
            cleanup.forEach { it.run() }
        }
    }

    override fun sign(
        payload: String,
        secretKey: AsymmetricSecretKey,
        footer: String?,
        implicitAssertion: String?
    ): String {
        try {
            // Verify key version.
            val keyMaterial = secretKey.getKeyMaterialFor(Version.V1, Purpose.PUBLIC)

            val payloadBytes = payload.toByteArray(Charsets.UTF_8)
            val footerBytes = (footer ?: "").toByteArray(Charsets.UTF_8)

            val m2 = pae(HEADER_PUBLIC.toByteArray(Charsets.UTF_8), payloadBytes, footerBytes)
            val sig = rsaSign(m2, keyMaterial)

            val msig = ByteArray(sig.size + payloadBytes.size)
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
        implicitAssertion: String?
    ): String {
        // Verify key version.
        val keyMaterial = publicKey.getKeyMaterialFor(Version.V1, Purpose.PUBLIC)

        // Split token into sections
        val sections = split(token)

        // Check header
        checkHeader(token, sections, HEADER_PUBLIC)

        // Decode footer
        val decodedFooter = decodeFooter(token, sections, footer)

        // Verify
        val msig = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
            ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
        val s = ByteArray(RSA_SIGNATURE_LEN)
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
        if (!rsaVerify(m2, s, keyMaterial)) {
            throw SignatureVerificationException(token)
        }

        return m.toString(Charsets.UTF_8)
    }
}
