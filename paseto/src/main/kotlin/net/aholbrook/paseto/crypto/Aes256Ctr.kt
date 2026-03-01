package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.exception.ByteArrayLengthException
import org.bouncycastle.crypto.StreamCipher
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

internal fun aes256CtrCipher(forEncryption: Boolean, key: ByteArray, iv: ByteArray): StreamCipher {
    if (key.isEmpty()) {
        throw ByteArrayLengthException("key", key.size, 1, false)
    }
    if (iv.isEmpty()) {
        @Suppress("MagicNumber")
        throw ByteArrayLengthException("iv", iv.size, 8, false)
    }

    return SICBlockCipher.newInstance(AESEngine.newInstance()).also {
        it.init(forEncryption, ParametersWithIV(KeyParameter(key), iv))
    }
}

internal fun aes256CtrEncrypt(m: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
    if (m.isEmpty()) {
        throw ByteArrayLengthException("m", m.size, 1, false)
    }

    val cipher = aes256CtrCipher(true, key, iv)
    val cipherText = ByteArray(m.size)
    cipher.processBytes(m, 0, m.size, cipherText, 0)
    return cipherText
}

internal fun aes256CtrDecrypt(c: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
    if (c.isEmpty()) {
        throw ByteArrayLengthException("c", c.size, 1, false)
    }

    val cipher = aes256CtrCipher(false, key, iv)
    val clearText = ByteArray(c.size)
    cipher.processBytes(c, 0, c.size, clearText, 0)
    return clearText
}
