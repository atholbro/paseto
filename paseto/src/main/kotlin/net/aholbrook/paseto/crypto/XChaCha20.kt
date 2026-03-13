@file:Suppress("MagicNumber")

package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.exception.ByteArrayLengthException
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.RuntimeCryptoException
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.util.Pack

// See https://www.scottbrady91.com/C-Sharp/XChaCha20-Poly1305-dotnet
// and https://github.com/daviddesmet/NaCl.Core

private val SIGMA = intArrayOf(0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
internal const val XCHACHA20_POLY1305_IETF_NPUBBYTES = 24 // nonce length
internal const val XCHACHA20_POLY1305_IETF_ABYTES = 16

internal const val CHACHA20_NONCE_BYTES = 24
internal const val CHACHA20_KEY_BYTES = 32

internal fun aeadXChaCha20Poly1305IetfEncrypt(
    out: ByteArray,
    input: ByteArray,
    ad: ByteArray,
    nonce: ByteArray,
    key: ByteArray,
): Boolean {
    if (input.isEmpty()) {
        throw ByteArrayLengthException("in", input.size, 1, false)
    }
    if (ad.isEmpty()) {
        throw ByteArrayLengthException("ad", ad.size, 1, false)
    }
    if (key.isEmpty()) {
        throw ByteArrayLengthException("key", key.size, 1, false)
    }
    if (nonce.size != XCHACHA20_POLY1305_IETF_NPUBBYTES) {
        throw ByteArrayLengthException("nonce", nonce.size, XCHACHA20_POLY1305_IETF_NPUBBYTES)
    }
    if (out.size != input.size + XCHACHA20_POLY1305_IETF_ABYTES) {
        throw ByteArrayLengthException("out", out.size, input.size + XCHACHA20_POLY1305_IETF_ABYTES)
    }

    return chaCha20Poly1305(true, out, input, ad, nonce, key)
}

internal fun aeadXChaCha20Poly1305IetfDecrypt(
    out: ByteArray,
    input: ByteArray,
    ad: ByteArray,
    nonce: ByteArray,
    key: ByteArray,
): Boolean {
    if (input.isEmpty()) {
        throw ByteArrayLengthException("in", input.size, 1, false)
    }
    if (ad.isEmpty()) {
        throw ByteArrayLengthException("ad", ad.size, 1, false)
    }
    if (key.isEmpty()) {
        throw ByteArrayLengthException("key", key.size, 1, false)
    }
    if (nonce.size != XCHACHA20_POLY1305_IETF_NPUBBYTES) {
        throw ByteArrayLengthException("nonce", nonce.size, XCHACHA20_POLY1305_IETF_NPUBBYTES)
    }
    if (out.size != input.size - XCHACHA20_POLY1305_IETF_ABYTES) {
        throw ByteArrayLengthException("out", out.size, input.size - XCHACHA20_POLY1305_IETF_ABYTES)
    }

    return chaCha20Poly1305(false, out, input, ad, nonce, key)
}

internal fun chaCha20(out: ByteArray, input: ByteArray, nonce: ByteArray, key: ByteArray): Boolean {
    if (input.isEmpty()) {
        throw ByteArrayLengthException("in", input.size, 1, false)
    }
    if (key.size != CHACHA20_KEY_BYTES) {
        throw ByteArrayLengthException("key", key.size, CHACHA20_KEY_BYTES, false)
    }
    if (nonce.size !=
        CHACHA20_NONCE_BYTES
    ) {
        throw ByteArrayLengthException("nonce", nonce.size, CHACHA20_NONCE_BYTES, false)
    }
    if (out.size != input.size) {
        throw ByteArrayLengthException("out", out.size, input.size, false)
    }

    val iv = ByteArray(12)
    System.arraycopy(nonce, 16, iv, 4, 8)
    val subkey: ByteArray = createSubkey(nonce, key)

    try {
        val chacha = ChaCha7539Engine()
        chacha.init(true, ParametersWithIV(KeyParameter(subkey), iv))
        chacha.processBytes(input, 0, input.size, out, 0)

        return true
    } catch (_: IllegalArgumentException) {
        return false
    } catch (_: RuntimeCryptoException) {
        return false
    } finally {
        iv.fill(0)
        subkey.fill(0)
    }
}

private fun chaCha20Poly1305(
    encrypt: Boolean,
    out: ByteArray,
    input: ByteArray,
    ad: ByteArray,
    nonce: ByteArray,
    key: ByteArray,
): Boolean {
    val chacha = ChaCha20Poly1305()
    val iv = ByteArray(12)
    System.arraycopy(nonce, 16, iv, 4, 8)

    val subkey = createSubkey(nonce, key)

    try {
        val params: CipherParameters = ParametersWithIV(KeyParameter(subkey), iv)
        chacha.init(encrypt, params)
        chacha.processAADBytes(ad, 0, ad.size)

        val len = chacha.processBytes(input, 0, input.size, out, 0)
        chacha.doFinal(out, len)
        return true
    } catch (_: IllegalArgumentException) {
        return false
    } catch (_: RuntimeCryptoException) {
        return false
    } finally {
        iv.fill(0)
        subkey.fill(0)
    }
}

private fun createSubkey(nonce: ByteArray, key: ByteArray): ByteArray {
    val state = createState(nonce, key)

    try {
        shuffleState(state)

        val subkey = ByteArray(32)
        Pack.intToLittleEndian(state, 0, 4, subkey, 0)
        Pack.intToLittleEndian(state, 12, 4, subkey, 16)
        return subkey
    } finally {
        state.fill(0)
    }
}

private fun createState(nonce: ByteArray, key: ByteArray): IntArray {
    val state = IntArray(16)

    state[0] = SIGMA[0]
    state[1] = SIGMA[1]
    state[2] = SIGMA[2]
    state[3] = SIGMA[3]
    Pack.littleEndianToInt(key, 0, state, 4, 8)
    Pack.littleEndianToInt(nonce, 0, state, 12, 4)

    return state
}

private fun shuffleState(state: IntArray) {
    repeat(10) {
        quarterRound(state, 0, 4, 8, 12)
        quarterRound(state, 1, 5, 9, 13)
        quarterRound(state, 2, 6, 10, 14)
        quarterRound(state, 3, 7, 11, 15)
        quarterRound(state, 0, 5, 10, 15)
        quarterRound(state, 1, 6, 11, 12)
        quarterRound(state, 2, 7, 8, 13)
        quarterRound(state, 3, 4, 9, 14)
    }
}

private fun quarterRound(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
    s[a] += s[b]
    s[d] = s[d] xor s[a]
    s[d] = s[d] shl 16 or (s[d] ushr 16)

    s[c] += s[d]
    s[b] = s[b] xor s[c]
    s[b] = s[b] shl 12 or (s[b] ushr 20)

    s[a] += s[b]
    s[d] = s[d] xor s[a]
    s[d] = s[d] shl 8 or (s[d] ushr 24)

    s[c] += s[d]
    s[b] = s[b] xor s[c]
    s[b] = s[b] shl 7 or (s[b] ushr 25)
}
