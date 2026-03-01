package net.aholbrook.paseto.protocol

import net.aholbrook.paseto.UrlSafeNoPadding
import net.aholbrook.paseto.crypto.ECDSA_P384_BYTES
import net.aholbrook.paseto.crypto.RSA_SIGNATURE_LEN
import net.aholbrook.paseto.crypto.aes256CtrDecrypt
import net.aholbrook.paseto.crypto.aes256CtrEncrypt
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.crypto.ecdsaP384Sign
import net.aholbrook.paseto.crypto.ecdsaP384Verify
import net.aholbrook.paseto.crypto.generateNonce
import net.aholbrook.paseto.crypto.hkdfSha384
import net.aholbrook.paseto.crypto.hmacSha384
import net.aholbrook.paseto.crypto.p384SkToPk
import net.aholbrook.paseto.crypto.pae
import net.aholbrook.paseto.crypto.rsaSign
import net.aholbrook.paseto.crypto.rsaVerify
import net.aholbrook.paseto.decodeOrNull
import net.aholbrook.paseto.exception.InvalidHeaderException
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.SignatureVerificationException
import kotlin.io.encoding.Base64

private const val VERSION = "v3"
private const val HEADER_PUBLIC: String = VERSION + SEPARATOR + PURPOSE_PUBLIC + SEPARATOR // v1.public.
private val HKDF_INFO_EK: ByteArray = "paseto-encryption-key".toByteArray(Charsets.UTF_8)
private val HKDF_INFO_AK: ByteArray = "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8)

object PasetoV3 : Paseto {
    override val version: Version = Version.V3
    override val supportsImplicitAssertion: Boolean = false

    override fun encrypt(payload: String, key: SymmetricKey, footer: String?, implicitAssertion: String?): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            // Verify key version.
            val k = key.getKeyMaterialFor(Version.V3, Purpose.LOCAL)

            val h = "v3.local."
            val m = payload.toByteArray(Charsets.UTF_8)
            val f = (footer ?: "").toByteArray(Charsets.UTF_8)
            val i = (implicitAssertion ?: "").toByteArray(Charsets.UTF_8)

            // Generate n
            val n = generateNonce(32)

            // Create ek/ak for AEAD
            val tmp = hkdfSha384(48, k, HKDF_INFO_EK + n, null)
            val ek = ByteArray(32)
            val n2 = ByteArray(16)
            System.arraycopy(tmp, 0, ek, 0, ek.size)
            cleanup.add { ek.fill(0) }
            System.arraycopy(tmp, 32, n2, 0, n2.size)
            cleanup.add { n2.fill(0) }
            tmp.fill(0)
            val ak = hkdfSha384(48, k, HKDF_INFO_AK + n, null)
            cleanup.add { ak.fill(0) }

            val c = aes256CtrEncrypt(m, ek, n2)
            val preAuth = pae(h.toByteArray(Charsets.UTF_8), n, c, f, i)
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

    override fun decrypt(token: String, key: SymmetricKey, footer: String?, implicitAssertion: String?): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            // Verify key version.
            val k = key.getKeyMaterialFor(Version.V3, Purpose.LOCAL)
            val h = "v3.local."
            val sections = split(token)
            val f = decodeFooter(token, sections, footer) // TODO review
            val i = (implicitAssertion ?: "").toByteArray(Charsets.UTF_8)

            // Check header
            if (!token.startsWith(h)) {
                throw InvalidHeaderException(sections.version + SEPARATOR + sections.purpose + SEPARATOR, h, token)
            }

            // Decrypt
            val nct = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
                ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
            val n = ByteArray(32)
            val t = ByteArray(48)
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

            // Create ek/ak for AEAD
            val tmp = hkdfSha384(48, k, HKDF_INFO_EK + n, null)
            val ek = ByteArray(32)
            val n2 = ByteArray(16)
            System.arraycopy(tmp, 0, ek, 0, ek.size)
            cleanup.add { ek.fill(0) }
            System.arraycopy(tmp, 32, n2, 0, n2.size)
            cleanup.add { n2.fill(0) }
            tmp.fill(0)
            val ak = hkdfSha384(48, k, HKDF_INFO_AK + n, null)
            cleanup.add { ak.fill(0) }

            val preAuth = pae(h.toByteArray(Charsets.UTF_8), n, c, f.toByteArray(Charsets.UTF_8), i)
            val t2 = hmacSha384(preAuth, ak)
            if (!t.constantTimeEquals(t2)) {
                throw SignatureVerificationException(token)
            }

            val m = aes256CtrDecrypt(c, ek, n2)
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
        implicitAssertion: String?,
    ): String {
        try {
            val sk = secretKey.getKeyMaterialFor(Version.V3, Purpose.PUBLIC)
            val pk = p384SkToPk(sk)
            val h = "v3.public."
            val m = payload.toByteArray(Charsets.UTF_8)
            val f = (footer ?: "").toByteArray(Charsets.UTF_8)
            val i = (implicitAssertion ?: "").toByteArray(Charsets.UTF_8)

            val m2 = pae(pk, h.toByteArray(Charsets.UTF_8), m, f, i)
            val sig = ecdsaP384Sign(m2, sk)

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
        implicitAssertion: String?,
    ): String {
        val pk = publicKey.getKeyMaterialFor(Version.V3, Purpose.PUBLIC)
        val h = "v3.public."
        val sections = split(token)
        val f = decodeFooter(token, sections, footer) // TODO review
        val i = (implicitAssertion ?: "").toByteArray(Charsets.UTF_8)

        // Check header
        if (!token.startsWith(h)) {
            throw InvalidHeaderException(sections.version + SEPARATOR + sections.purpose + SEPARATOR, h, token)
        }

        val sm = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
            ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
        val s = sm.copyOfRange(sm.size - ECDSA_P384_BYTES, sm.size)
        val m = sm.copyOfRange(0, sm.size - s.size)

        val m2 = pae(pk, h.toByteArray(Charsets.UTF_8), m, f.toByteArray(Charsets.UTF_8), i)
        if (!ecdsaP384Verify(s, m2, pk)) {
            throw SignatureVerificationException(token)
        }

        return m.toString(Charsets.UTF_8)
    }
}
