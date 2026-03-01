package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.exception.ByteArrayLengthException
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

internal const val ED25519_BYTES = 64
internal const val ED25519_PUBLICKEYBYTES = 32
internal const val ED25519_SECRETKEYBYTES = 64

internal fun ed25519Sign(sig: ByteArray, m: ByteArray, sk: ByteArray): Boolean {
    // check lengths
    if (sig.size != ED25519_BYTES) {
        throw ByteArrayLengthException("sig", sig.size, ED25519_BYTES)
    }
    if (m.isEmpty()) {
        throw ByteArrayLengthException("m", 0, 1, false)
    }
    if (sk.size != ED25519_SECRETKEYBYTES) {
        throw ByteArrayLengthException("sk", sk.size, ED25519_SECRETKEYBYTES)
    }

    val params: CipherParameters = Ed25519PrivateKeyParameters(sk, 0)
    val ed25519 = Ed25519Signer()
    ed25519.init(true, params)
    ed25519.update(m, 0, m.size)

    val result = ed25519.generateSignature()
    System.arraycopy(result, 0, sig, 0, sig.size)
    return true
}

internal fun ed25519Verify(sig: ByteArray, m: ByteArray, pk: ByteArray): Boolean {
    // check lengths
    if (sig.size != ED25519_BYTES) {
        throw ByteArrayLengthException("sig", sig.size, ED25519_BYTES)
    }
    if (m.isEmpty()) {
        throw ByteArrayLengthException("m", 0, 1, false)
    }
    if (pk.size != ED25519_PUBLICKEYBYTES) {
        throw ByteArrayLengthException("pk", pk.size, ED25519_PUBLICKEYBYTES)
    }

    val params: CipherParameters = Ed25519PublicKeyParameters(pk, 0)
    val ed25519 = Ed25519Signer()
    ed25519.init(false, params)
    ed25519.update(m, 0, m.size)
    return ed25519.verifySignature(sig)
}

internal fun ed25519SkToPk(sk: ByteArray): ByteArray {
    if (sk.size != ED25519_SECRETKEYBYTES) {
        throw ByteArrayLengthException("sk", sk.size, ED25519_SECRETKEYBYTES)
    }

    val pk = ByteArray(ED25519_PUBLICKEYBYTES)
    val params = Ed25519PrivateKeyParameters(sk, 0)
    val pkParams = params.generatePublicKey()
    System.arraycopy(pkParams.encoded, 0, pk, 0, pk.size)
    return pk
}

internal fun ed25519Generate(): Pair<ByteArray, ByteArray> {
    val skLen: Int = ED25519_SECRETKEYBYTES - ED25519_PUBLICKEYBYTES
    val sk = ByteArray(ED25519_SECRETKEYBYTES)
    val pk = ByteArray(ED25519_PUBLICKEYBYTES)

    val params = Ed25519PrivateKeyParameters(rng)
    val pkParams = params.generatePublicKey()

    System.arraycopy(params.encoded, 0, sk, 0, skLen)
    System.arraycopy(pkParams.encoded, 0, sk, skLen, pk.size)
    System.arraycopy(sk, skLen, pk, 0, pk.size)

    return Pair(sk, pk)
}
