package net.aholbrook.paseto.crypto

import io.kotest.assertions.throwables.shouldThrow
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import net.aholbrook.paseto.exception.ByteArrayLengthException
import net.aholbrook.paseto.exception.CryptoProviderException
import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.InvalidCipherTextException
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
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

    class BufferedBlockCipherExceptionTests {
        @BeforeEach
        fun beforeEach() {
            mockkStatic("net.aholbrook.paseto.crypto.Aes256CtrKt")
            val mockBlockCipher = mockk<BufferedBlockCipher>(relaxed = true)
            every { mockBlockCipher.doFinal(any(), any()) } throws InvalidCipherTextException("mocked")
            every { aes256CtrCipher(any(), any(), any()) } returns mockBlockCipher
        }

        @AfterEach
        fun afterEach() {
            unmockkAll()
        }

        @Test
        @DisplayName("aes256CtrEncrypt correctly handles an InvalidCipherTextException if thrown")
        fun aes256CtrEncrypt_InvalidCipherTextException() {
            shouldThrow<CryptoProviderException> {
                aes256CtrEncrypt(m, key, iv)
            }
        }

        @Test
        @DisplayName("aes256CtrDecrypt correctly handles an InvalidCipherTextException if thrown")
        fun aes256CtrDecrypt_InvalidCipherTextException() {
            val m = ByteArray(16)
            val key = ByteArray(16)
            val iv = ByteArray(8)

            shouldThrow<CryptoProviderException> {
                aes256CtrDecrypt(m, key, iv)
            }
        }
    }
}
