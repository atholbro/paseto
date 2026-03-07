@file:Suppress("MagicNumber")

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
import net.aholbrook.paseto.exception.InvalidHeaderException
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.SignatureVerificationException
import net.aholbrook.paseto.protocol.key.AsymmetricPublicKey
import net.aholbrook.paseto.protocol.key.AsymmetricSecretKey
import net.aholbrook.paseto.protocol.key.SymmetricKey
import kotlin.io.encoding.Base64

private val HKDF_INFO_EK: ByteArray = "paseto-encryption-key".toByteArray(Charsets.UTF_8)
private val HKDF_INFO_AK: ByteArray = "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8)

internal object PasetoV1 : Paseto {
    override val version: Version = Version.V1
    override val supportsImplicitAssertion: Boolean = false

    private fun getNonce(m: ByteArray, n: ByteArray) = hmacSha384(m, n).copyOfRange(0, 32)

    override fun encrypt(m: ByteArray, key: SymmetricKey, footer: String, implicitAssertion: String): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            val k = key.getKeyMaterialFor(Version.V1, Purpose.LOCAL)
            val h = "v1.local."
            val f = footer.toByteArray(Charsets.UTF_8)
            val b = generateNonce(32)
            cleanup.add { b.fill(0) }
            val n = getNonce(m, b)

            val salt = n.copyOfRange(0, HKDF_SALT_LEN)
            val nonce = n.copyOfRange(HKDF_SALT_LEN, HKDF_SALT_LEN * 2)

            // Create ek/ak for AEAD
            val ek = hkdfExtractAndExpand(salt, k, HKDF_INFO_EK)
            cleanup.add { ek.fill(0) }
            val ak = hkdfExtractAndExpand(salt, k, HKDF_INFO_AK)
            cleanup.add { ak.fill(0) }

            val c = aes256CtrEncrypt(m, ek, nonce)
            val preAuth = pae(h.toByteArray(Charsets.UTF_8), n, c, f)
            val t = hmacSha384(preAuth, ak)

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
        footer: String?,
        implicitAssertion: String,
    ): Pair<String, String> {
        val cleanup = mutableListOf<Runnable>()

        try {
            val k = key.getKeyMaterialFor(Version.V1, Purpose.LOCAL)
            val h = "v1.local."
            val sections = split(token)
            val f = decodeFooter(token, sections, footer)

            // Check header
            if (!token.startsWith(h)) {
                throw InvalidHeaderException(sections.version + SEPARATOR + sections.purpose + SEPARATOR, h, token)
            }

            // Decrypt
            val nct = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
                ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
            // verify length
            if (nct.size < 32 + SHA384_OUT_LEN + 1) {
                throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                    minLength = 32 + SHA384_OUT_LEN + 1
                }
            }
            val n = nct.copyOfRange(0, 32)
            val t = nct.copyOfRange(nct.size - SHA384_OUT_LEN, nct.size)
            val c = nct.copyOfRange(32, nct.size - SHA384_OUT_LEN)

            // Split N into salt/nonce
            val salt = n.copyOfRange(0, HKDF_SALT_LEN)
            val nonce = n.copyOfRange(HKDF_SALT_LEN, HKDF_SALT_LEN * 2)

            // Create ek/ak for AEAD
            val ek = hkdfExtractAndExpand(salt, k, HKDF_INFO_EK)
            cleanup.add { ek.fill(0) }
            val ak = hkdfExtractAndExpand(salt, k, HKDF_INFO_AK)
            cleanup.add { ak.fill(0) }

            val preAuth = pae(h.toByteArray(Charsets.UTF_8), n, c, f.toByteArray(Charsets.UTF_8))
            val t2 = hmacSha384(preAuth, ak)
            if (!t.constantTimeEquals(t2)) {
                throw SignatureVerificationException(token)
            }

            val m = aes256CtrDecrypt(c, ek, nonce)

            return Pair(m.toString(Charsets.UTF_8), f)
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
            val k = secretKey.getKeyMaterialFor(Version.V1, Purpose.PUBLIC)
            val h = "v1.public."
            val f = footer.toByteArray(Charsets.UTF_8)

            val m2 = pae(h.toByteArray(Charsets.UTF_8), m, f)
            val sig = rsaSign(m2, k)

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
        val pk = publicKey.getKeyMaterialFor(Version.V1, Purpose.PUBLIC)
        val h = "v1.public."
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
        if (sm.size < RSA_SIGNATURE_LEN + 1) {
            throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                minLength = RSA_SIGNATURE_LEN + 1
            }
        }
        val s = sm.copyOfRange(sm.size - RSA_SIGNATURE_LEN, sm.size)
        val m = sm.copyOfRange(0, sm.size - RSA_SIGNATURE_LEN)

        val m2 = pae(h.toByteArray(Charsets.UTF_8), m, f.toByteArray(Charsets.UTF_8))
        if (!rsaVerify(m2, s, pk)) {
            throw SignatureVerificationException(token)
        }

        return Pair(m.toString(Charsets.UTF_8), f)
    }
}
