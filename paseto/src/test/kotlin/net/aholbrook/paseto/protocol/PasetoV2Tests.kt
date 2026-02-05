package net.aholbrook.paseto.protocol

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import net.aholbrook.paseto.crypto.aeadXChaCha20Poly1305IetfDecrypt
import net.aholbrook.paseto.crypto.aeadXChaCha20Poly1305IetfEncrypt
import net.aholbrook.paseto.crypto.ed25519Sign
import net.aholbrook.paseto.crypto.ed25519Verify
import net.aholbrook.paseto.exception.DecryptionException
import net.aholbrook.paseto.exception.EncryptionException
import net.aholbrook.paseto.exception.InvalidHeaderException
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.SignatureVerificationException
import net.aholbrook.paseto.exception.SigningException
import net.aholbrook.paseto.keyV2Local
import net.aholbrook.paseto.keyV2Public
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class PasetoV2Tests {
    @Test
    fun `v2 does not support implicitAssertions`() {
        withClue("PasetoV2.supportsImplicitAssertion") {
            PasetoV2.supportsImplicitAssertion shouldBe false
        }
    }

    @Test
    fun local_missingSections() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV2.decrypt("", keyV2Local)
        }

        ex.reason shouldBe PasetoParseException.Reason.MISSING_SECTIONS
        ex.minLength shouldBe 0
    }

    @Test
    fun public_missingSections() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV2.verify("", keyV2Public.publicKey)
        }

        ex.reason shouldBe PasetoParseException.Reason.MISSING_SECTIONS
        ex.minLength shouldBe 0
    }

    @Test
    fun local_payloadLength() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV2.decrypt("v2.local.YWIK", keyV2Local)
        }

        ex.reason shouldBe PasetoParseException.Reason.PAYLOAD_LENGTH
        ex.minLength shouldBe 25
    }

    @Test
    fun public_payloadLength() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV2.verify("v2.public.YWIK", keyV2Public.publicKey)
        }

        ex.reason shouldBe PasetoParseException.Reason.PAYLOAD_LENGTH
        ex.minLength shouldBe 65
    }

    @Test
    fun local_encryptError() {
        mockkStatic("net.aholbrook.paseto.crypto.XChaCha20Kt")
        every { aeadXChaCha20Poly1305IetfEncrypt(any(), any(), any(), any(), any()) } returns false

        try {
            shouldThrow<EncryptionException> {
                PasetoV2.encrypt("abc", keyV2Local, null, null)
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun local_decryptError() {
        mockkStatic("net.aholbrook.paseto.crypto.XChaCha20Kt")
        every { aeadXChaCha20Poly1305IetfDecrypt(any(), any(), any(), any(), any()) } returns false

        try {
            val encrypted = PasetoV2.encrypt("abc", keyV2Local, null, null)
            shouldThrow<DecryptionException> {
                PasetoV2.decrypt(encrypted, keyV2Local)
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
                PasetoV2.sign("abc", keyV2Public.secretKey!!, null, null)
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
            val signed = PasetoV2.sign("abc", keyV2Public.secretKey!!, null, null)
            shouldThrow<SignatureVerificationException> {
                PasetoV2.verify(signed, keyV2Public.publicKey, null, null)
            }
        } finally {
            unmockkAll()
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["v1", "v4"])
    fun local_rejectsIncorrectVersions(version: String) {
        shouldThrow<InvalidHeaderException> {
            PasetoV2.decrypt("${version}.local.abc", keyV2Local)
        }
    }

    @Test
    fun local_rejectsIncorrectPurpose() {
        shouldThrow<InvalidHeaderException> {
            PasetoV2.decrypt("v2.public.abc", keyV2Local)
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["v1", "v4"])
    fun public_rejectsIncorrectVersions(version: String) {
        shouldThrow<InvalidHeaderException> {
            PasetoV2.verify("${version}.public.abc", keyV2Public.publicKey)
        }
    }

    @Test
    fun public_rejectsIncorrectPurpose() {
        shouldThrow<InvalidHeaderException> {
            PasetoV2.verify("v2.local.abc", keyV2Public.publicKey)
        }
    }

    @Test
    fun local_rejectsPaddedBase64() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV2.decrypt("v2.local.YWJjCg==", keyV2Local)
        }
        ex.reason shouldBe PasetoParseException.Reason.INVALID_BASE64
    }

    @Test
    fun public_rejectsPaddedBase64() {
        val ex = shouldThrow<PasetoParseException> {
            PasetoV2.verify("v2.public.YWJjCg==", keyV2Public.publicKey)
        }
        ex.reason shouldBe PasetoParseException.Reason.INVALID_BASE64
    }
}
