package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.exception.ByteArrayLengthException
import net.aholbrook.paseto.exception.CryptoProviderException
import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

internal fun aes256CtrCipher(forEncryption: Boolean, key: ByteArray, iv: ByteArray): BufferedBlockCipher {
    if (key.isEmpty()) {
        throw ByteArrayLengthException("key", key.size, 1, false)
    }
    if (iv.isEmpty()) {
        @Suppress("MagicNumber")
        throw ByteArrayLengthException("iv", iv.size, 8, false)
    }

    return BufferedBlockCipher(SICBlockCipher(AESEngine())).apply {
        init(forEncryption, ParametersWithIV(KeyParameter(key), iv))
    }
}

internal fun aes256CtrEncrypt(m: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
    try {
        if (m.isEmpty()) {
            throw ByteArrayLengthException("m", m.size, 1, false)
        }

        val cipher = aes256CtrCipher(true, key, iv)
        val cipherText = ByteArray(cipher.getOutputSize(m.size))
        val len = cipher.processBytes(m, 0, m.size, cipherText, 0)
        cipher.doFinal(cipherText, len)

        return cipherText
    } catch (ex: InvalidCipherTextException) {
        throw CryptoProviderException("Invalid cipher text in aes256CtrEncrypt.", ex)
    }
}

internal fun aes256CtrDecrypt(c: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
    try {
        if (c.isEmpty()) {
            throw ByteArrayLengthException("c", c.size, 1, false)
        }

        val cipher = aes256CtrCipher(false, key, iv)
        val clearText = ByteArray(cipher.getOutputSize(c.size))
        val len = cipher.processBytes(c, 0, c.size, clearText, 0)
        cipher.doFinal(clearText, len)

        return clearText
    } catch (ex: InvalidCipherTextException) {
        throw CryptoProviderException("Invalid cipher text in aes256CtrDecrypt.", ex)
    }
}
