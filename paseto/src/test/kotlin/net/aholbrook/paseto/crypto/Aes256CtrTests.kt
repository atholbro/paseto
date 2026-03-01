package net.aholbrook.paseto.crypto

import io.kotest.assertions.throwables.shouldThrow
import net.aholbrook.paseto.exception.ByteArrayLengthException
import org.junit.jupiter.api.Test

private val m = ByteArray(16)
private val key = ByteArray(16)
private val iv = ByteArray(8)

class Aes256CtrTests {
    @Test
    fun aes256CtrEncrypt_emptyMessage() {
        shouldThrow<ByteArrayLengthException> {
            aes256CtrEncrypt(ByteArray(0), key, iv)
        }
    }

    @Test
    fun aes256CtrEncrypt_emptyKey() {
        shouldThrow<ByteArrayLengthException> {
            aes256CtrEncrypt(m, ByteArray(0), iv)
        }
    }

    @Test
    fun aes256CtrEncrypt_emptyIv() {
        shouldThrow<ByteArrayLengthException> {
            aes256CtrEncrypt(m, key, ByteArray(0))
        }
    }

    @Test
    fun aes256CtrDecrypt_emptyCipherText() {
        shouldThrow<ByteArrayLengthException> {
            aes256CtrDecrypt(ByteArray(0), key, iv)
        }
    }

    @Test
    fun aes256CtrDecrypt_emptyKey() {
        shouldThrow<ByteArrayLengthException> {
            aes256CtrDecrypt(m, ByteArray(0), iv)
        }
    }

    @Test
    fun aes256CtrDecrypt_emptyIv() {
        shouldThrow<ByteArrayLengthException> {
            aes256CtrDecrypt(m, key, ByteArray(0))
        }
    }
}
