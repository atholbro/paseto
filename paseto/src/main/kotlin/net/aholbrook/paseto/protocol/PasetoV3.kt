@file:Suppress("MagicNumber", "DuplicatedCode")

package net.aholbrook.paseto.protocol

import net.aholbrook.paseto.UrlSafeNoPadding
import net.aholbrook.paseto.crypto.ECDSA_P384_BYTES
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
import net.aholbrook.paseto.decodeOrNull
import net.aholbrook.paseto.exception.DecryptionException
import net.aholbrook.paseto.exception.InvalidHeaderException
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.SignatureVerificationException
import net.aholbrook.paseto.exception.SigningException
import net.aholbrook.paseto.protocol.key.AsymmetricPublicKey
import net.aholbrook.paseto.protocol.key.AsymmetricSecretKey
import net.aholbrook.paseto.protocol.key.SymmetricKey
import kotlin.io.encoding.Base64

private val HKDF_INFO_EK: ByteArray = "paseto-encryption-key".toByteArray(Charsets.UTF_8)
private val HKDF_INFO_AK: ByteArray = "paseto-auth-key-for-aead".toByteArray(Charsets.UTF_8)

internal object PasetoV3 : Paseto {
    override val version: Version = Version.V3
    override val supportsImplicitAssertion: Boolean = true

    override fun encrypt(m: ByteArray, key: SymmetricKey, footer: String, implicitAssertion: String): String {
        val cleanup = mutableListOf<Runnable>()

        try {
            val k = key.getKeyMaterialFor(Version.V3, Purpose.LOCAL)
            val h = "v3.local."
            val f = footer.toByteArray(Charsets.UTF_8)
            val i = implicitAssertion.toByteArray(Charsets.UTF_8)
            val n = generateNonce(32)

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
            key.internalClear()
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
            // Verify key version.
            val k = key.getKeyMaterialFor(Version.V3, Purpose.LOCAL)
            val h = "v3.local."
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
            // verify length
            if (nct.size < 81) {
                throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                    minLength = 81
                }
            }
            val n = nct.copyOfRange(0, 32)
            val t = nct.copyOfRange(nct.size - 48, nct.size)
            val c = nct.copyOfRange(n.size, nct.size - t.size)

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
                throw DecryptionException(token)
            }

            val m = aes256CtrDecrypt(c, ek, n2)
            return Pair(m.toString(Charsets.UTF_8), f)
        } finally {
            key.internalClear()
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
            val sk = secretKey.getKeyMaterialFor(Version.V3, Purpose.PUBLIC)
            val pk = p384SkToPk(sk)
            val h = "v3.public."
            val f = footer.toByteArray(Charsets.UTF_8)
            val i = implicitAssertion.toByteArray(Charsets.UTF_8)

            val m2 = pae(pk, h.toByteArray(Charsets.UTF_8), m, f, i)
            val sig = ByteArray(ECDSA_P384_BYTES)
            if (!ecdsaP384Sign(sig, m2, sk)) {
                throw SigningException(m)
            }

            return h + Base64.UrlSafeNoPadding.encode(m + sig) +
                if (f.isEmpty()) {
                    ""
                } else {
                    ".${Base64.UrlSafeNoPadding.encode(f)}"
                }
        } finally {
            secretKey.internalClear()
        }
    }

    override fun verify(
        token: String,
        publicKey: AsymmetricPublicKey,
        footer: String?,
        implicitAssertion: String,
    ): Pair<String, String> {
        val pk = publicKey.getKeyMaterialFor(Version.V3, Purpose.PUBLIC)
        val h = "v3.public."
        val sections = split(token)
        val f = decodeFooter(token, sections, footer)
        val i = implicitAssertion.toByteArray(Charsets.UTF_8)

        // Check header
        if (!token.startsWith(h)) {
            throw InvalidHeaderException(sections.version + SEPARATOR + sections.purpose + SEPARATOR, h, token)
        }

        val sm = Base64.UrlSafeNoPadding.decodeOrNull(sections.payload)
            ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
        if (sm.size < ECDSA_P384_BYTES) {
            throw PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token).apply {
                minLength = ECDSA_P384_BYTES
            }
        }
        val s = sm.copyOfRange(sm.size - ECDSA_P384_BYTES, sm.size)
        val m = sm.copyOfRange(0, sm.size - s.size)

        val m2 = pae(pk, h.toByteArray(Charsets.UTF_8), m, f.toByteArray(Charsets.UTF_8), i)
        if (!ecdsaP384Verify(s, m2, pk)) {
            throw SignatureVerificationException(token)
        }

        return Pair(m.toString(Charsets.UTF_8), f)
    }
}
