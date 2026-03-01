package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.exception.ByteArrayLengthException
import net.aholbrook.paseto.exception.KeyV3Exception
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.sec.ECPrivateKey
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.util.BigIntegers
import java.math.BigInteger

internal const val ECDSA_P384_BYTES = 96
internal const val ECDSA_P384_PUBLICKEYBYTES = 49
internal const val ECDSA_P384_SECRETKEYBYTES = 48

internal fun ecdsaP384Sign(m: ByteArray, sk: ByteArray, enforceLowS: Boolean = false): ByteArray {
    if (m.isEmpty()) {
        throw ByteArrayLengthException("m", 0, 1, false)
    }
    if (sk.size !=
        ECDSA_P384_SECRETKEYBYTES
    ) {
        throw ByteArrayLengthException("sk", sk.size, ECDSA_P384_SECRETKEYBYTES)
    }

    val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
    val params = ECDomainParameters(curveParams.curve, curveParams.g, curveParams.n, curveParams.h)

    val d = BigInteger(1, sk)
    if (d.signum() <= 0 || d >= params.n) {
        throw KeyV3Exception("Invalid P-384 private key")
    }
    val secretKey = ECPrivateKeyParameters(d, params)

    val signer = ECDSASigner(HMacDSAKCalculator(SHA384Digest()))
    signer.init(true, secretKey)

    val digest = SHA384Digest()
    val hash = ByteArray(digest.digestSize)
    digest.update(m, 0, m.size)
    digest.doFinal(hash, 0)

    val components = signer.generateSignature(hash)
    val r = components[0]
    var s = components[1]
    if (enforceLowS && s > params.n shr 1) {
        s = params.n - s
    }

    return BigIntegers.asUnsignedByteArray(ECDSA_P384_BYTES / 2, r) +
        BigIntegers.asUnsignedByteArray(ECDSA_P384_BYTES / 2, s)
}

internal fun ecdsaP384Verify(sig: ByteArray, m: ByteArray, pk: ByteArray, enforceLowS: Boolean = false): Boolean {
    if (sig.size != ECDSA_P384_BYTES) {
        throw ByteArrayLengthException("sig", sig.size, ECDSA_P384_BYTES)
    }
    if (m.isEmpty()) {
        throw ByteArrayLengthException("m", 0, 1, false)
    }
    p384VerifyPk(pk)

    val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
    val params = ECDomainParameters(curveParams.curve, curveParams.g, curveParams.n, curveParams.h)

    val q = curveParams.curve.decodePoint(pk)
    val publicKey = ECPublicKeyParameters(q, params)
    val r = BigInteger(1, sig.copyOfRange(0, ECDSA_P384_BYTES / 2))
    val s = BigInteger(1, sig.copyOfRange(ECDSA_P384_BYTES / 2, sig.size))

    if (r.signum() <= 0 || r >= params.n) {
        return false
    }
    if (s.signum() <= 0 || s >= params.n) {
        return false
    }
    if (enforceLowS && s > params.n shr 1) {
        return false
    }

    val digest = SHA384Digest()
    val hash = ByteArray(digest.digestSize)
    digest.update(m, 0, m.size)
    digest.doFinal(hash, 0)

    val verifier = ECDSASigner()
    verifier.init(false, publicKey)

    return verifier.verifySignature(hash, r, s)
}

internal fun p384SkToPk(sk: ByteArray): ByteArray {
    if (sk.size != ECDSA_P384_SECRETKEYBYTES) {
        throw ByteArrayLengthException("sk", sk.size, ECDSA_P384_SECRETKEYBYTES)
    }

    val params = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
    val d = BigInteger(1, sk)
    if (d.signum() <= 0 || d >= params.n) {
        throw KeyV3Exception("Invalid P-384 private key")
    }
    val q = params.g.multiply(d).normalize()
    return q.getEncoded(true)
}

internal fun p384VerifyPk(pk: ByteArray) {
    if (pk.size != ECDSA_P384_PUBLICKEYBYTES) {
        throw ByteArrayLengthException("pk", pk.size, ECDSA_P384_PUBLICKEYBYTES)
    }
    if (pk[0] != 0x02.toByte() && pk[0] != 0x03.toByte()) {
        throw KeyV3Exception("must use point compression")
    }

    try {
        val params = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val q = try {
            params.curve.decodePoint(pk)
        } catch (ex: IllegalArgumentException) {
            throw KeyV3Exception("decode point", ex)
        }

        if (q.isInfinity) {
            throw KeyV3Exception("Point at infinity")
        }
        if (!q.isValid) {
            throw KeyV3Exception("Point not on curve")
        }
    } catch (e: IllegalArgumentException) {
        throw KeyV3Exception(e.message ?: "")
    }
}

internal fun p384EncodeSkPkcs8(sk: ByteArray): ByteArray {
    if (sk.size != ECDSA_P384_SECRETKEYBYTES) {
        throw ByteArrayLengthException("sk", sk.size, ECDSA_P384_SECRETKEYBYTES)
    }
    val params = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
    val d = BigInteger(1, sk)
    if (d.signum() <= 0 || d >= params.n) {
        throw KeyV3Exception("Invalid P-384 private key")
    }
    val secretKey = ECPrivateKey(384, d, null, SECObjectIdentifiers.secp384r1)
    return PrivateKeyInfo(
        AlgorithmIdentifier(
            X9ObjectIdentifiers.id_ecPublicKey,
            SECObjectIdentifiers.secp384r1,
        ),
        secretKey,
    ).encoded
}

internal fun p384DecodeSkPkcs8(der: ByteArray): ByteArray {
    val params = PrivateKeyFactory.createKey(der) as? ECPrivateKeyParameters
        ?: throw KeyV3Exception("Private key is not on secp384r1")
    val domain = params.parameters
    val expected = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)

    if (domain.curve != expected.curve || domain.g != expected.g || domain.n != expected.n || domain.h != expected.h) {
        throw KeyV3Exception("Private key is not on secp384r1")
    }

    if (params.d.signum() <= 0 || params.d >= domain.n) {
        throw KeyV3Exception("Invalid private key")
    }

    return BigIntegers.asUnsignedByteArray(ECDSA_P384_SECRETKEYBYTES, params.d)
}

internal fun p384EncodeSkSec1(sk: ByteArray): ByteArray {
    if (sk.size != ECDSA_P384_SECRETKEYBYTES) {
        throw ByteArrayLengthException("sk", sk.size, ECDSA_P384_SECRETKEYBYTES)
    }
    val params = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
    val d = BigInteger(1, sk)
    if (d.signum() <= 0 || d >= params.n) {
        throw KeyV3Exception("Invalid P-384 private key")
    }
    val secretKey = ECPrivateKey(384, d, null, SECObjectIdentifiers.secp384r1)
    return secretKey.encoded
}

internal fun p384DecodeSkSec1(der: ByteArray): ByteArray {
    val key = ECPrivateKey.getInstance(ASN1Primitive.fromByteArray(der))
    val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
    key.parametersObject?.let { params ->
        when (params) {
            is ASN1ObjectIdentifier -> {
                if (params != SECObjectIdentifiers.secp384r1) {
                    throw KeyV3Exception("SEC1 key not on secp384r1")
                }
            }

            else -> {
                throw KeyV3Exception("Unsupported curve parameters")
            }
        }
    } ?: throw KeyV3Exception("SEC1 key must include curve parameters")
    val d = key.key
    if (d.signum() <= 0 || d >= curveParams.n) {
        throw KeyV3Exception("Invalid P-384 private key")
    }

    return BigIntegers.asUnsignedByteArray(ECDSA_P384_SECRETKEYBYTES, d)
}

internal fun p384EncodePkSpki(pk: ByteArray): ByteArray {
    val params = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
    val point = try {
        params.curve.decodePoint(pk)
    } catch (ex: IllegalArgumentException) {
        throw KeyV3Exception("decode point", ex)
    }

    if (point.isInfinity) {
        throw KeyV3Exception("Point at infinity")
    }
    if (!point.isValid) {
        throw KeyV3Exception("Point not on curve")
    }

    return SubjectPublicKeyInfo(
        AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp384r1),
        point.getEncoded(true),
    ).encoded
}

internal fun p384DecodePkSpki(der: ByteArray): ByteArray {
    val params = PublicKeyFactory.createKey(der) as? ECPublicKeyParameters
        ?: throw KeyV3Exception("Public key is not on secp384r1")
    val domain = params.parameters
    val expected = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)

    if (domain.curve != expected.curve || domain.g != expected.g || domain.n != expected.n || domain.h != expected.h) {
        throw KeyV3Exception("Public key is not on secp384r1")
    }

    if (params.q.isInfinity) {
        throw KeyV3Exception("Point at infinity")
    }
    if (!params.q.isValid) {
        throw KeyV3Exception("Point not on curve")
    }

    return params.q.getEncoded(true)
}

internal fun p384Generate(): Pair<ByteArray, ByteArray> {
    val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
    val params = ECDomainParameters(curveParams.curve, curveParams.g, curveParams.n, curveParams.h)
    val keyGen = ECKeyPairGenerator()
    keyGen.init(ECKeyGenerationParameters(params, rng))
    val keyPair = keyGen.generateKeyPair()
    val secretKey = keyPair.private as ECPrivateKeyParameters
    val publicKey = keyPair.public as ECPublicKeyParameters

    return Pair(
        BigIntegers.asUnsignedByteArray(ECDSA_P384_SECRETKEYBYTES, secretKey.d),
        publicKey.q.normalize().getEncoded(true),
    )
}
