package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.exception.ByteArrayLengthException
import net.aholbrook.paseto.exception.CryptoProviderException
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.asn1.pkcs.RSAPublicKey
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.crypto.CryptoException
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.engines.RSABlindedEngine
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.signers.PSSSigner
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator
import java.io.IOException
import java.math.BigInteger

internal const val SHA384_OUT_LEN = 48
internal const val RSA_SIGNATURE_LEN = 256
internal const val RSA_KEY_SIZE = 2048
internal val E = BigInteger.valueOf(65537L)

internal fun pssSha384(forSigning: Boolean, key: ByteArray): PSSSigner {
    try {
        val salt = ByteArray(SHA384_OUT_LEN)
        rng.nextBytes(salt)
        // RSA-PSS, SHA-384, MGF1(SHA-384), 48 byte salt length, 0xBC trailer
        val pss = PSSSigner(
            RSABlindedEngine(),
            SHA384Digest(),
            SHA384Digest(),
            SHA384_OUT_LEN,
            0xBC.toByte()
        )

        if (forSigning) {
            pss.init(true, PrivateKeyFactory.createKey(key))
        } else {
            pss.init(false, PublicKeyFactory.createKey(key))
        }

        return pss
    } catch (e: IOException) {
        throw CryptoProviderException("IOException", e)
    }
}

internal fun rsaSign(m: ByteArray, privateKey: ByteArray): ByteArray {
    if (m.isEmpty()) {
        throw ByteArrayLengthException("m", m.size, 1, false)
    }
    if (privateKey.isEmpty()) {
        throw ByteArrayLengthException("privateKey", privateKey.size, 1, false)
    }

    try {
        val pss = pssSha384(true, privateKey)
        pss.update(m, 0, m.size)
        return pss.generateSignature()
    } catch (e: CryptoException) {
        // Not documented
        throw CryptoProviderException("CryptoException", e)
    }
}

internal fun rsaVerify(m: ByteArray, sig: ByteArray, publicKey: ByteArray): Boolean {
    if (m.isEmpty()) {
        throw ByteArrayLengthException("m", m.size, 1, false)
    }
    if (sig.size != RSA_SIGNATURE_LEN) {
        throw ByteArrayLengthException("sig", sig.size, RSA_SIGNATURE_LEN, true)
    }
    if (publicKey.isEmpty()) {
        throw ByteArrayLengthException("publicKey", publicKey.size, 1, false)
    }

    val pss = pssSha384(false, publicKey)
    pss.update(m, 0, m.size)
    return pss.verifySignature(sig)
}

internal fun rsaSkToPk(secretKey: ByteArray): ByteArray {
    val secretKeyInfo = PrivateKeyInfo.getInstance(secretKey)
    val rsa = RSAPrivateKey.getInstance(secretKeyInfo.parsePrivateKey())
    val publicKeyParams = RSAKeyParameters(
        false,
        rsa.modulus,
        rsa.publicExponent
    )
    val algo = AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)

    return KeyUtil.getEncodedSubjectPublicKeyInfo(
        algo,
        RSAPublicKey(rsa.modulus, rsa.publicExponent)
    )
}

internal fun rsaGenerate(): Pair<ByteArray, ByteArray> {
    val keyGen = RSAKeyPairGenerator()
    keyGen.init(
        RSAKeyGenerationParameters(
            E,
            rng,
            RSA_KEY_SIZE,
            PrimeCertaintyCalculator.getDefaultCertainty(RSA_KEY_SIZE)
        )
    )
    val pair = keyGen.generateKeyPair()

    val pub = pair.public as RSAKeyParameters
    val pri = pair.private as RSAPrivateCrtKeyParameters

    // As in BCRSAPrivateKey / BCRSAPublicKey
    val algo = AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)
    val publicKey = KeyUtil.getEncodedSubjectPublicKeyInfo(
        algo, RSAPublicKey(
            pub.modulus,
            pub.exponent
        )
    )
    val privateKey = KeyUtil.getEncodedPrivateKeyInfo(
        algo, RSAPrivateKey(
            pri.modulus,
            pri.publicExponent,
            pri.exponent,
            pri.p,
            pri.q,
            pri.dp,
            pri.dq,
            pri.qInv
        )
    )

    return Pair<ByteArray, ByteArray>(privateKey, publicKey)
}
