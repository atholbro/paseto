package net.aholbrook.paseto.crypto

import io.kotest.assertions.throwables.shouldThrow
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import net.aholbrook.paseto.exception.ByteArrayLengthException
import net.aholbrook.paseto.exception.CryptoException as PasetoCryptoException
import org.bouncycastle.crypto.CryptoException
import org.bouncycastle.crypto.signers.PSSSigner
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

class RsaPssSha384Tests {
    @Test
    fun rsaSign_badKey() {
        shouldThrow<PasetoCryptoException> {
            rsaSign("test".toByteArray(), byteArrayOf(0x01))
        }
    }

    @Test
    fun rsaSign_emptyMessage() {
        shouldThrow<ByteArrayLengthException> {
            rsaSign(ByteArray(0), ByteArray(1217))
        }
    }

    @Test
    fun rsaSign_emptyPrivateKey() {
        shouldThrow<ByteArrayLengthException> {
            rsaSign("test".toByteArray(), ByteArray(0))
        }
    }

    @Test
    fun rsaVerify_badKey() {
        shouldThrow<PasetoCryptoException> {
            rsaVerify("test".toByteArray(), ByteArray(RSA_SIGNATURE_LEN), byteArrayOf(0x01))
        }
    }

    @Test
    fun rsaVerify_emptyMessage() {
        shouldThrow<ByteArrayLengthException> {
            rsaVerify(ByteArray(0), ByteArray(RSA_SIGNATURE_LEN), ByteArray(294))
        }
    }

    @Test
    fun rsaVerify_shortSignature() {
        shouldThrow<ByteArrayLengthException> {
            rsaVerify("test".toByteArray(), ByteArray(RSA_SIGNATURE_LEN - 1), ByteArray(294))
        }
    }

    @Test
    fun rsaVerify_longSignature() {
        shouldThrow<ByteArrayLengthException> {
            rsaVerify("test".toByteArray(), ByteArray(RSA_SIGNATURE_LEN + 1), ByteArray(294))
        }
    }

    @Test
    fun rsaVerify_emptyPublicKey() {
        shouldThrow<ByteArrayLengthException> {
            rsaVerify("test".toByteArray(), ByteArray(RSA_SIGNATURE_LEN), ByteArray(0))
        }
    }

    class PSSSignerExceptionTests {
        @BeforeEach
        fun beforeEach() {
            mockkStatic("net.aholbrook.paseto.crypto.RsaPssSha384Kt")
            val mockSigner = mockk<PSSSigner>(relaxed = true)
            every { mockSigner.generateSignature() } throws CryptoException("mocked", RuntimeException())
            every { pssSha384(any(), any()) } returns mockSigner
        }

        @AfterEach
        fun afterEach() {
            unmockkAll()
        }

        @Test
        @DisplayName("rsaSign correctly handles a CryptoException if thrown")
        fun rsaSign_PasetoCryptoException() {
            val m = ByteArray(16)
            val keyPair = rsaGenerate()

            shouldThrow<PasetoCryptoException> {
                rsaSign(m, keyPair.first)
            }
        }
    }
}
