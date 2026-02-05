package net.aholbrook.paseto.protocol

import net.aholbrook.paseto.crypto.ECDSA_P384_PUBLICKEYBYTES
import net.aholbrook.paseto.crypto.ECDSA_P384_SECRETKEYBYTES
import net.aholbrook.paseto.crypto.ED25519_PUBLICKEYBYTES
import net.aholbrook.paseto.crypto.ED25519_SECRETKEYBYTES
import net.aholbrook.paseto.crypto.ed25519Generate
import net.aholbrook.paseto.crypto.ed25519SkToPk
import net.aholbrook.paseto.crypto.p384DecodePkSpki
import net.aholbrook.paseto.crypto.p384DecodeSkPkcs8
import net.aholbrook.paseto.crypto.p384DecodeSkSec1
import net.aholbrook.paseto.crypto.p384EncodePkSpki
import net.aholbrook.paseto.crypto.p384EncodeSkPkcs8
import net.aholbrook.paseto.crypto.p384EncodeSkSec1
import net.aholbrook.paseto.crypto.p384Generate
import net.aholbrook.paseto.crypto.p384SkToPk
import net.aholbrook.paseto.crypto.p384VerifyPk
import net.aholbrook.paseto.crypto.randomBytes
import net.aholbrook.paseto.crypto.rsaGenerate
import net.aholbrook.paseto.crypto.rsaSkToPk
import net.aholbrook.paseto.exception.KeyLengthException
import net.aholbrook.paseto.exception.KeyPemUnsupportedTypeException
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.exception.Pkcs12LoadException
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayInputStream
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStreamReader
import java.io.StringWriter
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import kotlin.io.encoding.Base64

class AsymmetricPublicKey private constructor(
    private val material: ByteArray,
    val version: Version,
) {
    internal val purpose: Purpose = Purpose.PUBLIC

    init {
        val allowedKeySizes = when (version) {
            Version.V1 -> arrayOf()
            Version.V2 -> arrayOf(ED25519_PUBLICKEYBYTES)
            Version.V3 -> arrayOf(ECDSA_P384_PUBLICKEYBYTES)
            Version.V4 -> arrayOf(ED25519_PUBLICKEYBYTES)
        }

        if (allowedKeySizes.isNotEmpty() && !allowedKeySizes.contains(material.size)) {
            throw KeyLengthException(material.size, allowedKeySizes)
        }

        if (version == Version.V3) {
            p384VerifyPk(material)
        }
    }

    fun toHex(): String = Hex.toHexString(material)
    fun toBase64Url(): String = Base64.UrlSafe.encode(material)
    fun toPem(): String {
        val der = when (version) {
            Version.V1 -> material
            Version.V3 -> p384EncodePkSpki(material)
            Version.V2, Version.V4 -> Ed25519PublicKeyParameters(material, 0).let {
                SubjectPublicKeyInfo(
                    AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    it.encoded
                ).encoded
            }
        }
        return StringWriter().also { sw ->
            PemWriter(sw).use { pw ->
                pw.writeObject(PemObject("PUBLIC KEY", der))
            }
        }.toString()
    }

    internal fun getKeyMaterialFor(version: Version, purpose: Purpose): ByteArray {
        if (this.version != version) { throw KeyVersionException(version, this.version) }
        if (this.purpose != purpose) { throw KeyPurposeException(purpose.toString(), this.purpose.toString()) }
        return material
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) { return true }
        if (javaClass != other?.javaClass) { return false }

        other as AsymmetricPublicKey

        if (version != other.version) { return false }
        if (purpose != other.purpose) { return false }
        if (!material.contentEquals(other.material)) { return false }

        return true
    }

    override fun hashCode(): Int {
        var result = material.contentHashCode()
        result = 31 * result + version.hashCode()
        result = 31 * result + purpose.hashCode()
        return result
    }

    override fun toString(): String {
        return "AsymmetricPublicKey(material=*****, version=$version, purpose=$purpose)"
    }

    companion object {
        @JvmStatic
        fun ofRawBytes(material: ByteArray, version: Version) = AsymmetricPublicKey(material, version)

        @JvmStatic
        fun ofHex(hex: String, version: Version) = AsymmetricPublicKey(Hex.decode(hex), version)

        @JvmStatic
        fun ofBase64Url(b64: String, version: Version) = AsymmetricPublicKey(decodeBase64Url(b64), version)

        @JvmStatic
        fun ofPem(pem: String, version: Version) = ofPem(pem.toByteArray(Charsets.UTF_8), version)

        @JvmStatic
        fun ofPem(pem: ByteArray, version: Version): AsymmetricPublicKey {
            val (type, der) = decodePem(pem)

            if (type != "PUBLIC KEY") { throw KeyPemUnsupportedTypeException(type) }

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
                rsaSkToPk(secretKey.getKeyMaterialFor(Version.V1, Purpose.PUBLIC)), Version.V1
            )
            Version.V2 -> ofRawBytes(
                ed25519SkToPk(secretKey.getKeyMaterialFor(Version.V2, Purpose.PUBLIC)), Version.V2
            )
            Version.V3 -> ofRawBytes(
                p384SkToPk(secretKey.getKeyMaterialFor(Version.V1, Purpose.PUBLIC)), Version.V3
            )
            Version.V4 -> ofRawBytes(
                ed25519SkToPk(secretKey.getKeyMaterialFor(Version.V4, Purpose.PUBLIC)), Version.V4
            )
        }
    }
}

class AsymmetricSecretKey private constructor(
    private val material: ByteArray,
    val version: Version,
) {
    internal val purpose: Purpose = Purpose.PUBLIC

    init {
        val allowedKeySizes = when (version) {
            Version.V1 -> arrayOf()
            Version.V2 -> arrayOf(ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES, ED25519_SECRETKEYBYTES)
            Version.V3 -> arrayOf(ECDSA_P384_SECRETKEYBYTES)
            Version.V4 -> arrayOf(ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES, ED25519_SECRETKEYBYTES)
        }

        if (allowedKeySizes.isNotEmpty() && !allowedKeySizes.contains(material.size)) {
            throw KeyLengthException(material.size, allowedKeySizes)
        }
    }

    fun toHex(): String = Hex.toHexString(material)
    fun toBase64Url(): String = Base64.UrlSafe.encode(material)
    fun toPem(): String {
        val der = when (version) {
            Version.V1 -> material
            Version.V3 -> p384EncodeSkSec1(material)
            Version.V2, Version.V4 -> {
                val rawKey = if (material.size == ED25519_SECRETKEYBYTES) {
                    material.copyOfRange(0, ED25519_PUBLICKEYBYTES)
                } else {
                    material
                }
                PrivateKeyInfo(
                    AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    DEROctetString(rawKey),
                ).encoded
            }
        }
        return StringWriter().also { sw ->
            PemWriter(sw).use { pw ->
                pw.writeObject(PemObject("PRIVATE KEY", der))
            }
        }.toString()
    }

    internal fun getKeyMaterialFor(version: Version, purpose: Purpose): ByteArray {
        if (this.version != version) { throw KeyVersionException(version, this.version) }
        if (this.purpose != purpose) { throw KeyPurposeException(purpose.toString(), this.purpose.toString()) }
        return material
    }

    private fun normalizeMaterial(material: ByteArray): ByteArray = when (version) {
        Version.V2 -> material.copyOf(ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES)
        Version.V4 -> material.copyOf(ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES)
        else -> material
    }

    internal fun clear() {
        material.fill(0)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) { return true }
        if (javaClass != other?.javaClass) { return false }

        other as AsymmetricSecretKey

        if (version != other.version) { return false }
        if (purpose != other.purpose) { return false }
        if (!normalizeMaterial(material).contentEquals(normalizeMaterial(other.material))) { return false }

        return true
    }

    override fun hashCode(): Int {
        var result = normalizeMaterial(material).contentHashCode()
        result = 31 * result + version.hashCode()
        result = 31 * result + purpose.hashCode()
        return result
    }

    override fun toString(): String {
        return "AsymmetricSecretKey(material=*****, version=$version, purpose=$purpose)"
    }

    companion object {
        @JvmStatic
        fun ofRawBytes(material: ByteArray, version: Version) = AsymmetricSecretKey(material, version)

        @JvmStatic
        fun ofHex(hex: String, version: Version) = AsymmetricSecretKey(Hex.decode(hex), version)

        @JvmStatic
        fun ofBase64Url(b64: String, version: Version) = AsymmetricSecretKey(decodeBase64Url(b64), version)

        @JvmStatic
        fun ofPem(pem: String, version: Version) = ofPem(pem.toByteArray(Charsets.UTF_8), version)

        @JvmStatic
        fun ofPem(pem: ByteArray, version: Version): AsymmetricSecretKey {
            val (type, der) = decodePem(pem)

            val encoded = when (version) {
                Version.V1 -> when (type) {
                    "RSA PRIVATE KEY" -> pkcs1RsaToPkcs8(der)
                    "PRIVATE KEY" -> der
                    else -> throw KeyPemUnsupportedTypeException(type)
                }
                Version.V2 -> {
                    if (type != "PRIVATE KEY") { throw KeyPemUnsupportedTypeException(type) }
                    (PrivateKeyFactory.createKey(der) as Ed25519PrivateKeyParameters).encoded
                }
                Version.V3 -> when (type) {
                    "EC PRIVATE KEY" -> p384DecodeSkSec1(der)
                    "PRIVATE KEY" -> p384DecodeSkPkcs8(der)
                    else -> throw KeyPemUnsupportedTypeException(type)
                }
                Version.V4 -> {
                    if (type != "PRIVATE KEY") { throw KeyPemUnsupportedTypeException(type) }
                    (PrivateKeyFactory.createKey(der) as Ed25519PrivateKeyParameters).encoded
                }
            }

            return AsymmetricSecretKey(encoded, version)
        }
    }
}

class SymmetricKey private constructor(
    private val material: ByteArray,
    val version: Version,
) {
    internal val purpose: Purpose = Purpose.LOCAL

    init {
        val allowedKeySizes = when (version) {
            Version.V1 -> arrayOf(32)
            Version.V2 -> arrayOf(32)
            Version.V3 -> arrayOf(32)
            Version.V4 -> arrayOf(32)
        }

        if (!allowedKeySizes.contains(material.size)) {
            throw KeyLengthException(material.size, allowedKeySizes)
        }
    }

    fun toHex(): String = Hex.toHexString(material)
    fun toBase64Url(): String = Base64.UrlSafe.encode(material)

    internal fun getKeyMaterialFor(version: Version, purpose: Purpose): ByteArray {
        if (this.version != version) { throw KeyVersionException(version, this.version) }
        if (this.purpose != purpose) { throw KeyPurposeException(purpose.toString(), this.purpose.toString()) }
        return material
    }

    internal fun clear() {
        material.fill(0)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) { return true }
        if (javaClass != other?.javaClass) { return false }

        other as SymmetricKey

        if (version != other.version) { return false }
        if (purpose != other.purpose) { return false }
        if (!material.contentEquals(other.material)) { return false }

        return true
    }

    override fun hashCode(): Int {
        var result = material.contentHashCode()
        result = 31 * result + version.hashCode()
        result = 31 * result + purpose.hashCode()
        return result
    }

    override fun toString(): String {
        return "SymmetricKey(material=*****, version=$version, purpose=$purpose)"
    }

    companion object {
        @JvmStatic
        fun generate(version: Version) = ofRawBytes(randomBytes(32), version)

        @JvmStatic
        fun ofRawBytes(material: ByteArray, version: Version) = SymmetricKey(material, version)

        @JvmStatic
        fun ofHex(hex: String, version: Version) = SymmetricKey(Hex.decode(hex), version)

        @JvmStatic
        fun ofBase64Url(b64: String, version: Version) = SymmetricKey(decodeBase64Url(b64), version)
    }
}

class KeyPair(val secretKey: AsymmetricSecretKey?, val publicKey: AsymmetricPublicKey) {
    init {
        if (secretKey != null && secretKey.version != publicKey.version) {
            throw KeyVersionException(secretKey.version, publicKey.version)
        }
        if (secretKey != null && secretKey.purpose != Purpose.PUBLIC) {
            throw KeyPurposeException(Purpose.PUBLIC.toString(), secretKey.purpose.toString())
        }
        if (publicKey.purpose != Purpose.PUBLIC) {
            throw KeyPurposeException(Purpose.PUBLIC.toString(), publicKey.purpose.toString())
        }
    }

    val version: Version = publicKey.version

    override fun equals(other: Any?): Boolean {
        if (this===other) { return true }
        if (javaClass!=other?.javaClass) { return false }

        other as KeyPair

        if (version!=other.version) { return false }
        if (secretKey!=other.secretKey) { return false }
        if (publicKey!=other.publicKey) { return false }

        return true
    }

    override fun hashCode(): Int {
        var result = secretKey?.hashCode() ?: 0
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + version.hashCode()
        return result
    }


    companion object {
        @JvmStatic
        fun generate(version: Version): KeyPair {
            val (secretKey, publicKey) = when(version) {
                Version.V1 -> rsaGenerate()
                Version.V2 -> ed25519Generate()
                Version.V3 -> p384Generate()
                Version.V4 -> ed25519Generate()
            }

            return KeyPair(
                secretKey = AsymmetricSecretKey.ofRawBytes(secretKey, version),
                publicKey = AsymmetricPublicKey.ofRawBytes(publicKey, version),
            )
        }

        @JvmStatic
        @JvmOverloads
        fun pkcs12Load(
            keystoreFile: String,
            keystorePass: String,
            alias: String,
            keyPass: String = keystorePass
        ): KeyPair {
            try {
                val p12 = KeyStore.getInstance("PKCS12")
                p12.load(FileInputStream(keystoreFile), keystorePass.toCharArray())

                val privateKey = p12.getKey(alias, keyPass.toCharArray()) as? PrivateKey
                    ?: throw Pkcs12LoadException(Pkcs12LoadException.Reason.PRIVATE_KEY_NOT_FOUND)
                val cert = p12.getCertificate(alias)
                    ?: throw Pkcs12LoadException(Pkcs12LoadException.Reason.PUBLIC_KEY_NOT_FOUND)
                val publicKey = cert.publicKey

                return KeyPair(
                    AsymmetricSecretKey.ofRawBytes(privateKey.encoded, Version.V1),
                    AsymmetricPublicKey.ofRawBytes(publicKey.encoded, Version.V1)
                )
            } catch (e: FileNotFoundException) {
                throw Pkcs12LoadException(e)
            } catch (e: CertificateException) {
                throw Pkcs12LoadException(e) // Unlikely to ever throw.
            } catch (e: NoSuchAlgorithmException) {
                throw Pkcs12LoadException(e) // Unlikely to occur on any modern jvm.
            } catch (e: UnrecoverableKeyException) {
                throw Pkcs12LoadException(e)
            } catch (e: IOException) {
                throw Pkcs12LoadException(e)
            } catch (e: KeyStoreException) {
                throw RuntimeException(e) // This can only occur if you forget to call load, thus this will never throw.
            }
        }
    }
}

private fun decodeBase64Url(b64: String): ByteArray = Base64.UrlSafe.decode(b64)

private fun decodePem(pem: ByteArray): Pair<String, ByteArray> {
    val obj = PemReader(InputStreamReader(ByteArrayInputStream(pem))).use { reader ->
        reader.readPemObject()
    }
    return Pair(obj.type, obj.content)
}

private fun pkcs1RsaToPkcs8(pkcs1Der: ByteArray): ByteArray {
    val rsa = RSAPrivateKey.getInstance(ASN1Primitive.fromByteArray(pkcs1Der))
    val alg = AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)
    return PrivateKeyInfo(alg, rsa).encoded
}
