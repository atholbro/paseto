package net.aholbrook.paseto.crypto

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import net.aholbrook.paseto.exception.ByteArrayLengthException
import org.junit.jupiter.api.Test

class Ed25519Tests {
    private val sig = ByteArray(ED25519_BYTES)
    private val msg = ByteArray(6)
    private val secretKey = ByteArray(ED25519_SECRETKEYBYTES)
    private val publicKey = ByteArray(ED25519_PUBLICKEYBYTES)

    @Test
    fun ed25519Sign_shortSig() {
        shouldThrow<ByteArrayLengthException> {
            ed25519Sign(ByteArray(ED25519_BYTES - 1), msg, secretKey)
        }
    }

    @Test
    fun ed25519Sign_longSig() {
        shouldThrow<ByteArrayLengthException> {
            ed25519Sign(ByteArray(ED25519_BYTES + 1), msg, secretKey)
        }
    }

    @Test
    fun ed25519Sign_emptyMessage() {
        shouldThrow<ByteArrayLengthException> {
            ed25519Sign(sig, ByteArray(0), secretKey)
        }
    }

    @Test
    fun ed25519Sign_shortSecretKey() {
        shouldThrow<ByteArrayLengthException> {
            ed25519Sign(sig, msg, ByteArray(ED25519_SECRETKEYBYTES - 1))
        }
    }

    @Test
    fun ed25519Sign_longSecretKey() {
        shouldThrow<ByteArrayLengthException> {
            ed25519Sign(sig, msg, ByteArray(ED25519_SECRETKEYBYTES + 1))
        }
    }

    @Test
    fun ed25519Verify_shortSig() {
        shouldThrow<ByteArrayLengthException> {
            ed25519Verify(ByteArray(ED25519_BYTES - 1), msg, publicKey)
        }
    }

    @Test
    fun ed25519Verify_longSig() {
        shouldThrow<ByteArrayLengthException> {
            ed25519Verify(ByteArray(ED25519_BYTES + 1), msg, publicKey)
        }
    }

    @Test
    fun ed25519Verify_emptyMessage() {
        shouldThrow<ByteArrayLengthException> {
            ed25519Verify(sig, ByteArray(0), publicKey)
        }
    }

    @Test
    fun ed25519Verify_shortPublicKey() {
        shouldThrow<ByteArrayLengthException> {
            ed25519Verify(sig, msg, ByteArray(ED25519_PUBLICKEYBYTES - 1))
        }
    }

    @Test
    fun ed25519Verify_longPublicKey() {
        shouldThrow<ByteArrayLengthException> {
            ed25519Verify(sig, msg, ByteArray(ED25519_PUBLICKEYBYTES + 1))
        }
    }

    @Test
    fun ed25519SkToPk_shortSecretKey() {
        shouldThrow<ByteArrayLengthException> {
            ed25519SkToPk(ByteArray(ED25519_SECRETKEYBYTES - 1))
        }
    }

    @Test
    fun ed25519SkToPk_longSecretKey() {
        shouldThrow<ByteArrayLengthException> {
            ed25519SkToPk(ByteArray(ED25519_SECRETKEYBYTES + 1))
        }
    }

    @Test
    fun ed25519Generate_ed25519SkToPk() {
        val (sk, pk) = ed25519Generate()
        ed25519SkToPk(sk) shouldBe pk
    }

    @Test
    fun ed25519Generate_works() {
        val (sk, pk) = ed25519Generate()
        val signature = ByteArray(ED25519_BYTES)

        ed25519SkToPk(sk.copyOf()) shouldBe pk
        ed25519Sign(signature, "test message".toByteArray(), sk) shouldBe true
        ed25519Verify(signature, "test message".toByteArray(), pk) shouldBe true
    }
}
