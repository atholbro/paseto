package net.aholbrook.paseto.protocol.key

import net.aholbrook.paseto.crypto.ED25519_PUBLICKEYBYTES
import net.aholbrook.paseto.crypto.ED25519_SECRETKEYBYTES
import net.aholbrook.paseto.crypto.ed25519SkToPk
import net.aholbrook.paseto.crypto.p384DecodePkSpki
import net.aholbrook.paseto.crypto.p384EncodePkSpki
import net.aholbrook.paseto.crypto.p384SkToPk
import net.aholbrook.paseto.crypto.p384VerifyPk
import net.aholbrook.paseto.crypto.rsaSkToPk
import net.aholbrook.paseto.exception.KeyLengthException
import net.aholbrook.paseto.exception.KeyPemUnsupportedTypeException
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.Version
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.util.encoders.Hex
import kotlin.io.encoding.Base64

class AsymmetricPublicKey private constructor(private val material: ByteArray, val version: Version) {
    internal val purpose: Purpose = Purpose.PUBLIC

    init {
        if (version.asymmetricPublicKeySize > -1) {
            if (version.asymmetricPublicKeySize != material.size) {
                throw KeyLengthException(material.size, arrayOf(version.asymmetricPublicKeySize))
            }
        }

        if (version == Version.V3) {
            p384VerifyPk(material)
        }
    }

    fun toHex(): String = Hex.toHexString(material)
    fun toBase64Url(): String = Base64.UrlSafe.encode(material)
    fun toPem(): String {
        val content = when (version) {
            Version.V1 -> material

            Version.V3 -> p384EncodePkSpki(material)

            Version.V2, Version.V4 -> Ed25519PublicKeyParameters(
                material.copyOfRange(0, ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES),
                0,
            ).let {
                SubjectPublicKeyInfo(
                    AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    it.encoded,
                ).encoded
            }
        }
        return pemEncode("PUBLIC KEY", content)
    }

    internal fun getKeyMaterialFor(version: Version, purpose: Purpose): ByteArray {
        if (this.version != version) {
            throw KeyVersionException(version, this.version)
        }
        if (this.purpose != purpose) {
            throw KeyPurposeException(purpose.toString(), this.purpose.toString())
        }
        return material
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (javaClass != other?.javaClass) {
            return false
        }

        other as AsymmetricPublicKey

        if (version != other.version) {
            return false
        }
        if (purpose != other.purpose) {
            return false
        }
        if (!material.contentEquals(other.material)) {
            return false
        }

        return true
    }

    override fun hashCode(): Int {
        var result = material.contentHashCode()
        result = 31 * result + version.hashCode()
        result = 31 * result + purpose.hashCode()
        return result
    }

    override fun toString(): String = "AsymmetricPublicKey(material=*****, version=$version, purpose=$purpose)"

    companion object {
        @JvmStatic
        fun ofRawBytes(material: ByteArray, version: Version) = AsymmetricPublicKey(material, version)

        @JvmStatic
        fun ofHex(hex: String, version: Version) = AsymmetricPublicKey(Hex.decode(hex), version)

        @JvmStatic
        fun ofBase64Url(b64: String, version: Version) = AsymmetricPublicKey(Base64.UrlSafe.decode(b64), version)

        @JvmStatic
        fun ofPem(pem: String, version: Version) = ofPem(pem.toByteArray(Charsets.UTF_8), version)

        @JvmStatic
        fun ofPem(pem: ByteArray, version: Version): AsymmetricPublicKey {
            val (type, der) = pemDecode(pem)

            if (type != "PUBLIC KEY") {
                throw KeyPemUnsupportedTypeException(type)
            }

            val encoded = when (version) {
                Version.V1 -> der
                Version.V2 -> (PublicKeyFactory.createKey(der) as Ed25519PublicKeyParameters).encoded
                Version.V3 -> p384DecodePkSpki(der)
                Version.V4 -> (PublicKeyFactory.createKey(der) as Ed25519PublicKeyParameters).encoded
            }

            return AsymmetricPublicKey(encoded, version)
        }

        @JvmStatic
        fun fromSecretKey(secretKey: AsymmetricSecretKey): AsymmetricPublicKey = when (secretKey.version) {
            Version.V1 -> ofRawBytes(
                rsaSkToPk(secretKey.getKeyMaterialFor(Version.V1, Purpose.PUBLIC)),
                Version.V1,
            )

            Version.V2 -> ofRawBytes(
                ed25519SkToPk(secretKey.getKeyMaterialFor(Version.V2, Purpose.PUBLIC)),
                Version.V2,
            )

            Version.V3 -> ofRawBytes(
                p384SkToPk(secretKey.getKeyMaterialFor(Version.V3, Purpose.PUBLIC)),
                Version.V3,
            )

            Version.V4 -> ofRawBytes(
                ed25519SkToPk(secretKey.getKeyMaterialFor(Version.V4, Purpose.PUBLIC)),
                Version.V4,
            )
        }
    }
}
