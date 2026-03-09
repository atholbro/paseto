package net.aholbrook.paseto.protocol

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.crypto.rsaVerify
import net.aholbrook.paseto.exception.InvalidHeaderException
import net.aholbrook.paseto.exception.SignatureVerificationException
import net.aholbrook.paseto.exception.TokenParseException
import net.aholbrook.paseto.keyV1Local
import net.aholbrook.paseto.keyV1Public
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class PasetoV1Tests {
    @Test
    fun `v1 does not support implicitAssertions`() {
        withClue("PasetoV1.supportsImplicitAssertion") {
            PasetoV1.supportsImplicitAssertion shouldBe false
        }
    }

    @Test
    fun local_missingSections() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV1.decrypt("", keyV1Local)
        }

        ex.reason shouldBe TokenParseException.Reason.MISSING_SECTIONS
        ex.minLength shouldBe 0
    }

    @Test
    fun public_missingSections() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV1.verify("", keyV1Public.publicKey)
        }

        ex.reason shouldBe TokenParseException.Reason.MISSING_SECTIONS
        ex.minLength shouldBe 0
    }

    @Test
    fun local_payloadLength() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV1.decrypt("v1.local.YWIK", keyV1Local)
        }

        ex.reason shouldBe TokenParseException.Reason.PAYLOAD_LENGTH
        ex.minLength shouldBe 81
    }

    @Test
    fun public_payloadLength() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV1.verify("v1.public.YWIK", keyV1Public.publicKey)
        }

        ex.reason shouldBe TokenParseException.Reason.PAYLOAD_LENGTH
        ex.minLength shouldBe 257
    }

    @Test
    fun local_verifyError() {
        mockkStatic("net.aholbrook.paseto.crypto.ConstantTimeEqualsKt")
        every { any<String>().constantTimeEquals("") } returns true
        every { any<ByteArray>().constantTimeEquals(any()) } returns false

        try {
            val encrypted = PasetoV1.encrypt("abc".toByteArray(Charsets.UTF_8), keyV1Local)
            shouldThrow<SignatureVerificationException> {
                PasetoV1.decrypt(encrypted, keyV1Local)
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun public_verifyError() {
        mockkStatic("net.aholbrook.paseto.crypto.RsaPssSha384Kt")
        every { rsaVerify(any(), any(), any()) } returns false

        try {
            val signed = PasetoV1.sign("abc".toByteArray(Charsets.UTF_8), keyV1Public.secretKey!!)
            shouldThrow<SignatureVerificationException> {
                PasetoV1.verify(signed, keyV1Public.publicKey)
            }
        } finally {
            unmockkAll()
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["v2", "v4"])
    fun local_rejectsIncorrectVersions(version: String) {
        val ex = shouldThrow<InvalidHeaderException> {
            PasetoV1.decrypt("$version.local.abc", keyV1Local)
        }
        ex.given shouldBe "$version.local."
        ex.expected shouldBe "v1.local."
        ex.token shouldBe "$version.local.abc"
    }

    @Test
    fun local_rejectsIncorrectPurpose() {
        val ex = shouldThrow<InvalidHeaderException> {
            PasetoV1.decrypt("v1.public.abc", keyV1Local)
        }
        ex.given shouldBe "v1.public."
        ex.expected shouldBe "v1.local."
        ex.token shouldBe "v1.public.abc"
    }

    @ParameterizedTest
    @ValueSource(strings = ["v2", "v4"])
    fun public_rejectsIncorrectVersions(version: String) {
        val ex = shouldThrow<InvalidHeaderException> {
            PasetoV1.verify("$version.public.abc", keyV1Public.publicKey)
        }
        ex.given shouldBe "$version.public."
        ex.expected shouldBe "v1.public."
        ex.token shouldBe "$version.public.abc"
    }

    @Test
    fun public_rejectsIncorrectPurpose() {
        val ex = shouldThrow<InvalidHeaderException> {
            PasetoV1.verify("v1.local.abc", keyV1Public.publicKey)
        }
        ex.given shouldBe "v1.local."
        ex.expected shouldBe "v1.public."
        ex.token shouldBe "v1.local.abc"
    }

    @Test
    fun local_rejectsPaddedBase64() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV1.decrypt("v1.local.YWJjCg==", keyV1Local)
        }
        ex.reason shouldBe TokenParseException.Reason.INVALID_BASE64
    }

    @Test
    fun public_rejectsPaddedBase64() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV1.verify("v1.public.YWJjCg==", keyV1Public.publicKey)
        }
        ex.reason shouldBe TokenParseException.Reason.INVALID_BASE64
    }
}
