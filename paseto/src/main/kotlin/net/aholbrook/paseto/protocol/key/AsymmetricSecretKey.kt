package net.aholbrook.paseto.protocol.key

import net.aholbrook.paseto.crypto.ED25519_PUBLICKEYBYTES
import net.aholbrook.paseto.crypto.ED25519_SECRETKEYBYTES
import net.aholbrook.paseto.crypto.ed25519SkToPk
import net.aholbrook.paseto.crypto.p384DecodeSkPkcs8
import net.aholbrook.paseto.crypto.p384DecodeSkSec1
import net.aholbrook.paseto.crypto.p384EncodeSkSec1
import net.aholbrook.paseto.crypto.rsaPkcs1ToPkcs8
import net.aholbrook.paseto.exception.KeyClearedException
import net.aholbrook.paseto.exception.KeyLengthException
import net.aholbrook.paseto.exception.KeyPemUnsupportedTypeException
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.Version
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.util.encoders.Hex
import kotlin.io.encoding.Base64

class AsymmetricSecretKey private constructor(material: ByteArray, val version: Version, val lifecycle: KeyLifecycle) {
    internal val purpose: Purpose = Purpose.PUBLIC
    private val material: ByteArray
    private var cleared: Boolean = false

    init {
        val allowedKeySizes = when (version) {
            Version.V1 -> arrayOf()

            Version.V2 -> arrayOf(
                version.asymmetricSecretKeySize,
                version.asymmetricSecretKeySize - version.asymmetricPublicKeySize,
            )

            Version.V3 -> arrayOf(version.asymmetricSecretKeySize)

            Version.V4 -> arrayOf(
                version.asymmetricSecretKeySize,
                version.asymmetricSecretKeySize - version.asymmetricPublicKeySize,
            )
        }

        if (allowedKeySizes.isNotEmpty() && !allowedKeySizes.contains(material.size)) {
            throw KeyLengthException(material.size, allowedKeySizes)
        }

        // Recreate public key if missing
        this.material = when (version) {
            Version.V2, Version.V4 -> {
                if (material.size != version.asymmetricSecretKeySize) {
                    material + ed25519SkToPk(material)
                } else {
                    material
                }
            }

            else -> material
        }
    }

    fun copy(lifecycle: KeyLifecycle = KeyLifecycle.EPHEMERAL): AsymmetricSecretKey =
        AsymmetricSecretKey(material.copyOf(), version, lifecycle)

    fun toHex(): String {
        if (cleared) throw KeyClearedException()
        return Hex.toHexString(material)
    }

    fun toBase64Url(): String {
        if (cleared) throw KeyClearedException()
        return Base64.UrlSafe.encode(material)
    }

    fun toPem(): String {
        if (cleared) throw KeyClearedException()

        val (content, type) = when (version) {
            Version.V1 -> Pair(material, "PRIVATE KEY")

            Version.V3 -> Pair(p384EncodeSkSec1(material), "EC PRIVATE KEY")

            Version.V2, Version.V4 -> {
                val rawKey = material.copyOfRange(0, ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES)

                Pair(
                    PrivateKeyInfo(
                        AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                        DEROctetString(rawKey),
                    ).encoded,
                    "PRIVATE KEY",
                )
            }
        }

        return pemEncode(type, content)
    }

    fun clear() {
        material.fill(0)
        cleared = true
    }

    internal fun internalClear() {
        if (lifecycle == KeyLifecycle.EPHEMERAL) clear()
    }

    internal fun getKeyMaterialFor(version: Version, purpose: Purpose): ByteArray {
        if (cleared) throw KeyClearedException()
        if (this.version != version) throw KeyVersionException(version, this.version)
        if (this.purpose != purpose) throw KeyPurposeException(purpose.toString(), this.purpose.toString())
        return material
    }

    private fun normalizeMaterial(material: ByteArray): ByteArray = when (version) {
        Version.V2 -> material.copyOf(ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES)
        Version.V4 -> material.copyOf(ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES)
        else -> material
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (javaClass != other?.javaClass) {
            return false
        }

        other as AsymmetricSecretKey

        if (version != other.version) {
            return false
        }
        if (purpose != other.purpose) {
            return false
        }
        if (!normalizeMaterial(material).contentEquals(normalizeMaterial(other.material))) {
            return false
        }

        return true
    }

    override fun hashCode(): Int {
        var result = normalizeMaterial(material).contentHashCode()
        result = 31 * result + version.hashCode()
        result = 31 * result + purpose.hashCode()
        return result
    }

    override fun toString(): String = "AsymmetricSecretKey(material=*****, version=$version, purpose=$purpose)"

    companion object {
        @JvmStatic
        fun ofRawBytes(material: ByteArray, version: Version, lifecycle: KeyLifecycle = KeyLifecycle.PERSISTENT) =
            AsymmetricSecretKey(material, version, lifecycle)

        @JvmStatic
        fun ofHex(hex: String, version: Version, lifecycle: KeyLifecycle = KeyLifecycle.PERSISTENT) =
            AsymmetricSecretKey(Hex.decode(hex), version, lifecycle)

        @JvmStatic
        fun ofBase64Url(b64: String, version: Version, lifecycle: KeyLifecycle = KeyLifecycle.PERSISTENT) =
            AsymmetricSecretKey(Base64.UrlSafe.decode(b64), version, lifecycle)

        @JvmStatic
        fun ofPem(pem: String, version: Version, lifecycle: KeyLifecycle = KeyLifecycle.PERSISTENT) =
            ofPem(pem.toByteArray(Charsets.UTF_8), version, lifecycle)

        @JvmStatic
        fun ofPem(
            pem: ByteArray,
            version: Version,
            lifecycle: KeyLifecycle = KeyLifecycle.PERSISTENT,
        ): AsymmetricSecretKey {
            val (type, content) = pemDecode(pem)

            val encoded = when (version) {
                Version.V1 -> when (type) {
                    "RSA PRIVATE KEY" -> rsaPkcs1ToPkcs8(content)
                    "PRIVATE KEY" -> content
                    else -> throw KeyPemUnsupportedTypeException(type)
                }

                Version.V2 -> {
                    if (type != "PRIVATE KEY") {
                        throw KeyPemUnsupportedTypeException(type)
                    }
                    (PrivateKeyFactory.createKey(content) as Ed25519PrivateKeyParameters).encoded
                }

                Version.V3 -> when (type) {
                    "EC PRIVATE KEY" -> p384DecodeSkSec1(content)
                    "PRIVATE KEY" -> p384DecodeSkPkcs8(content)
                    else -> throw KeyPemUnsupportedTypeException(type)
                }

                Version.V4 -> {
                    if (type != "PRIVATE KEY") {
                        throw KeyPemUnsupportedTypeException(type)
                    }
                    (PrivateKeyFactory.createKey(content) as Ed25519PrivateKeyParameters).encoded
                }
            }

            return AsymmetricSecretKey(encoded, version, lifecycle)
        }
    }
}
