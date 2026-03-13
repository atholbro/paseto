package net.aholbrook.paseto.crypto

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockkConstructor
import io.mockk.unmockkConstructor
import net.aholbrook.paseto.exception.ByteArrayLengthException
import org.bouncycastle.crypto.RuntimeCryptoException
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.junit.jupiter.api.Test

class XChaCha20Tests {
    private val encryptInput = ByteArray(6)
    private val encryptOut = ByteArray(encryptInput.size + XCHACHA20_POLY1305_IETF_ABYTES)
    private val decryptInput = encryptOut
    private val decryptOut = encryptInput
    private val ad = ByteArray(XCHACHA20_POLY1305_IETF_ABYTES)
    private val nonce = ByteArray(XCHACHA20_POLY1305_IETF_NPUBBYTES)
    private val key = ByteArray(32)

    @Test
    fun aeadXChaCha20Poly1305IetfEncrypt_emptyInput() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfEncrypt(encryptOut, ByteArray(0), ad, nonce, key)
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfEncrypt_emptyAd() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfEncrypt(encryptOut, encryptInput, ByteArray(0), nonce, key)
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfEncrypt_emptyKey() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfEncrypt(encryptOut, encryptInput, ad, nonce, ByteArray(0))
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfEncrypt_shortNonce() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfEncrypt(
                encryptOut,
                encryptInput,
                ad,
                ByteArray(XCHACHA20_POLY1305_IETF_NPUBBYTES - 1),
                key,
            )
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfEncrypt_longNonce() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfEncrypt(
                encryptOut,
                encryptInput,
                ad,
                ByteArray(XCHACHA20_POLY1305_IETF_NPUBBYTES + 1),
                key,
            )
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfEncrypt_outShort() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfEncrypt(
                out = ByteArray(encryptOut.size - 1),
                input = encryptInput,
                ad = ad,
                nonce = nonce,
                key = key,
            )
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfEncrypt_outLong() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfEncrypt(
                out = ByteArray(encryptOut.size + 1),
                input = encryptInput,
                ad = ad,
                nonce = nonce,
                key = key,
            )
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfDecrypt_emptyInput() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfDecrypt(decryptOut, ByteArray(0), ad, nonce, key)
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfDecrypt_emptyAd() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfDecrypt(decryptOut, encryptInput, ByteArray(0), nonce, key)
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfDecrypt_emptyKey() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfDecrypt(decryptOut, decryptInput, ad, nonce, ByteArray(0))
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfDecrypt_shortNonce() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfDecrypt(
                decryptOut,
                decryptInput,
                ad,
                ByteArray(XCHACHA20_POLY1305_IETF_NPUBBYTES - 1),
                key,
            )
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfDecrypt_longNonce() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfDecrypt(
                decryptOut,
                decryptInput,
                ad,
                ByteArray(XCHACHA20_POLY1305_IETF_NPUBBYTES + 1),
                key,
            )
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfDecrypt_outShort() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfDecrypt(
                out = ByteArray(decryptOut.size - 1),
                input = decryptInput,
                ad = ad,
                nonce = nonce,
                key = key,
            )
        }
    }

    @Test
    fun aeadXChaCha20Poly1305IetfDecrypt_outLong() {
        shouldThrow<ByteArrayLengthException> {
            aeadXChaCha20Poly1305IetfDecrypt(
                out = ByteArray(decryptOut.size + 1),
                input = decryptInput,
                ad = ad,
                nonce = nonce,
                key = key,
            )
        }
    }

    @Test
    fun chaCha20Poly1305_catchesIllegalArgumentException() {
        mockkConstructor(ChaCha20Poly1305::class)
        try {
            every {
                anyConstructed<ChaCha20Poly1305>().init(any(), any())
            } throws IllegalArgumentException("mocked")

            aeadXChaCha20Poly1305IetfDecrypt(decryptOut, decryptInput, ad, nonce, key) shouldBe false
        } finally {
            unmockkConstructor(ChaCha20Poly1305::class)
        }
    }

    @Test
    fun chaCha20Poly1305_catchesRuntimeCryptoException() {
        mockkConstructor(ChaCha20Poly1305::class)
        try {
            every {
                anyConstructed<ChaCha20Poly1305>().init(any(), any())
            } throws RuntimeCryptoException("mocked")

            aeadXChaCha20Poly1305IetfDecrypt(decryptOut, decryptInput, ad, nonce, key) shouldBe false
        } finally {
            unmockkConstructor(ChaCha20Poly1305::class)
        }
    }
}

class ChaCha20Tests {
    private val input = ByteArray(6)
    private val out = ByteArray(6)
    private val nonce = ByteArray(CHACHA20_NONCE_BYTES)
    private val key = ByteArray(CHACHA20_KEY_BYTES)

    @Test
    fun chaCha20_emptyInput() {
        shouldThrow<ByteArrayLengthException> {
            chaCha20(out, ByteArray(0), nonce, key)
        }
    }

    @Test
    fun chaCha20_keyShort() {
        shouldThrow<ByteArrayLengthException> {
            chaCha20(out, input, nonce, ByteArray(key.size - 1))
        }
    }

    @Test
    fun chaCha20_keyLong() {
        shouldThrow<ByteArrayLengthException> {
            chaCha20(out, input, nonce, ByteArray(key.size + 1))
        }
    }

    @Test
    fun chaCha20_nonceShort() {
        shouldThrow<ByteArrayLengthException> {
            chaCha20(out, input, ByteArray(nonce.size - 1), key)
        }
    }

    @Test
    fun chaCha20_nonceLong() {
        shouldThrow<ByteArrayLengthException> {
            chaCha20(out, input, ByteArray(nonce.size + 1), key)
        }
    }

    @Test
    fun chaCha20_outSizeShort() {
        shouldThrow<ByteArrayLengthException> {
            chaCha20(ByteArray(input.size - 1), input, nonce, key)
        }
    }

    @Test
    fun chaCha20_outSizeLong() {
        shouldThrow<ByteArrayLengthException> {
            chaCha20(ByteArray(input.size + 1), input, nonce, key)
        }
    }

    @Test
    fun chaCha20_returnsTrueOnSuccess() {
        chaCha20(out, input, nonce, key) shouldBe true
    }

    @Test
    fun chaCha20_catchesIllegalArgumentException() {
        mockkConstructor(ChaCha7539Engine::class)
        try {
            every {
                anyConstructed<ChaCha7539Engine>().init(any(), any())
            } throws IllegalArgumentException("mocked")

            chaCha20(out, input, nonce, key) shouldBe false
        } finally {
            unmockkConstructor(ChaCha7539Engine::class)
        }
    }

    @Test
    fun chaCha20_catchesRuntimeCryptoException() {
        mockkConstructor(ChaCha7539Engine::class)
        try {
            every {
                anyConstructed<ChaCha7539Engine>().init(any(), any())
            } throws RuntimeCryptoException("mocked")

            chaCha20(out, input, nonce, key) shouldBe false
        } finally {
            unmockkConstructor(ChaCha7539Engine::class)
        }
    }
}
