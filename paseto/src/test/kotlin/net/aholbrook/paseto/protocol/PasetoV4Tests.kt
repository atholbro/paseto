package net.aholbrook.paseto.protocol

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import net.aholbrook.paseto.crypto.chaCha20
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.crypto.ed25519Sign
import net.aholbrook.paseto.crypto.ed25519Verify
import net.aholbrook.paseto.exception.DecryptionException
import net.aholbrook.paseto.exception.EncryptionException
import net.aholbrook.paseto.exception.InvalidHeaderException
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.SignatureVerificationException
import net.aholbrook.paseto.exception.SigningException
import net.aholbrook.paseto.keyV4Local
import net.aholbrook.paseto.keyV4Public
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class PasetoV4Tests {
    @Test
    fun local_missingSections() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV4.decrypt("", keyV4Local)
        }

        ex.reason shouldBe PasetoParseException.Reason.MISSING_SECTIONS
        ex.minLength shouldBe 0
    }

    @Test
    fun public_missingSections() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV4.verify("", keyV4Public.publicKey)
        }

        ex.reason shouldBe PasetoParseException.Reason.MISSING_SECTIONS
        ex.minLength shouldBe 0
    }

    @Test
    fun public_payloadLength() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV4.verify("v4.public.YWIK", keyV4Public.publicKey)
        }

        ex.reason shouldBe PasetoParseException.Reason.PAYLOAD_LENGTH
        ex.minLength shouldBe 65
    }

    @Test
    fun local_encryptError() {
        mockkStatic("net.aholbrook.paseto.crypto.XChaCha20Kt")
        every { chaCha20(any(), any(), any(), any()) } returns false

        try {
            shouldThrow<EncryptionException> {
                PasetoV4.encrypt("abc".toByteArray(Charsets.UTF_8), keyV4Local, "", "")
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun local_constantTimeEqualsFailingThrowsDecryptionException() {
        mockkStatic("net.aholbrook.paseto.crypto.ConstantTimeEqualsKt")
        every { any<String>().constantTimeEquals("") } returns true

        try {
            val encrypted = PasetoV4.encrypt("abc".toByteArray(Charsets.UTF_8), keyV4Local)
            every { any<ByteArray>().constantTimeEquals(any()) } returns false
            shouldThrow<DecryptionException> {
                PasetoV4.decrypt(encrypted, keyV4Local)
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun local_decryptError() {
        mockkStatic("net.aholbrook.paseto.crypto.XChaCha20Kt")

        try {
            val encrypted = PasetoV4.encrypt("abc".toByteArray(Charsets.UTF_8), keyV4Local)
            every { chaCha20(any(), any(), any(), any()) } returns false
            shouldThrow<DecryptionException> {
                PasetoV4.decrypt(encrypted, keyV4Local)
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun public_signError() {
        mockkStatic("net.aholbrook.paseto.crypto.Ed25519Kt")
        every { ed25519Sign(any(), any(), any()) } returns false

        try {
            shouldThrow<SigningException> {
                PasetoV4.sign("abc".toByteArray(Charsets.UTF_8), keyV4Public.secretKey!!)
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun public_verifyError() {
        mockkStatic("net.aholbrook.paseto.crypto.Ed25519Kt")
        every { ed25519Verify(any(), any(), any()) } returns false

        try {
            val signed = PasetoV4.sign("abc".toByteArray(Charsets.UTF_8), keyV4Public.secretKey!!)
            shouldThrow<SignatureVerificationException> {
                PasetoV4.verify(signed, keyV4Public.publicKey)
            }
        } finally {
            unmockkAll()
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["v1", "v2"])
    fun local_rejectsIncorrectVersions(version: String) {
        shouldThrow<InvalidHeaderException> {
            PasetoV4.decrypt("$version.local.abc", keyV4Local)
        }
    }

    @Test
    fun local_rejectsIncorrectPurpose() {
        shouldThrow<InvalidHeaderException> {
            PasetoV4.decrypt("v4.public.abc", keyV4Local)
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["v1", "v2"])
    fun public_rejectsIncorrectVersions(version: String) {
        shouldThrow<InvalidHeaderException> {
            PasetoV4.verify("$version.public.abc", keyV4Public.publicKey)
        }
    }

    @Test
    fun public_rejectsIncorrectPurpose() {
        shouldThrow<InvalidHeaderException> {
            PasetoV4.verify("v4.local.abc", keyV4Public.publicKey)
        }
    }

    @Test
    fun local_rejectsPaddedBase64() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV4.decrypt("v4.local.YWJjCg==", keyV4Local)
        }
        ex.reason shouldBe PasetoParseException.Reason.INVALID_BASE64
    }

    @Test
    fun public_rejectsPaddedBase64() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV4.verify("v4.public.YWJjCg==", keyV4Public.publicKey)
        }
        ex.reason shouldBe PasetoParseException.Reason.INVALID_BASE64
    }
}
