package net.aholbrook.paseto.protocol

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import net.aholbrook.paseto.UrlSafeNoPadding
import net.aholbrook.paseto.crypto.ECDSA_P384_BYTES
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.crypto.ecdsaP384Sign
import net.aholbrook.paseto.crypto.ecdsaP384Verify
import net.aholbrook.paseto.exception.DecryptionException
import net.aholbrook.paseto.exception.InvalidHeaderException
import net.aholbrook.paseto.exception.SignatureVerificationException
import net.aholbrook.paseto.exception.SigningException
import net.aholbrook.paseto.exception.TokenParseException
import net.aholbrook.paseto.keyV3Local
import net.aholbrook.paseto.keyV3Public
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.io.encoding.Base64

class PasetoV3Tests {
    @Test
    fun local_missingSections() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV3.decrypt("", keyV3Local)
        }

        ex.reason shouldBe TokenParseException.Reason.MISSING_SECTIONS
        ex.minLength shouldBe 0
    }

    @ParameterizedTest
    @ValueSource(ints = [0, 80])
    fun local_incorrectPayloadLength(size: Int) {
        val payload = "v3.local.${Base64.UrlSafeNoPadding.encode(ByteArray(size))}"
        val ex = shouldThrow<TokenParseException> {
            PasetoV3.decrypt(payload, keyV3Local)
        }
        ex.reason shouldBe TokenParseException.Reason.PAYLOAD_LENGTH
        ex.minLength shouldBe 81
    }

    @Test
    fun public_missingSections() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV3.verify("", keyV3Public.publicKey)
        }

        ex.reason shouldBe TokenParseException.Reason.MISSING_SECTIONS
        ex.minLength shouldBe 0
    }

    @Test
    fun public_payloadLength() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV3.verify("v3.public.YWIK", keyV3Public.publicKey)
        }

        ex.reason shouldBe TokenParseException.Reason.PAYLOAD_LENGTH
        ex.minLength shouldBe ECDSA_P384_BYTES
    }

    @Test
    fun local_constantTimeEqualsFailingThrowsDecryptionException() {
        mockkStatic("net.aholbrook.paseto.crypto.ConstantTimeEqualsKt")
        every { any<String>().constantTimeEquals("") } returns true

        try {
            val encrypted = PasetoV3.encrypt("abc".toByteArray(Charsets.UTF_8), keyV3Local, "", "")
            every { any<ByteArray>().constantTimeEquals(any()) } returns false
            shouldThrow<DecryptionException> {
                PasetoV3.decrypt(encrypted, keyV3Local)
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun public_signError() {
        mockkStatic("net.aholbrook.paseto.crypto.EcdsaKt")
        every { ecdsaP384Sign(any(), any(), any()) } returns false

        try {
            shouldThrow<SigningException> {
                PasetoV3.sign("abc".toByteArray(Charsets.UTF_8), keyV3Public.secretKey!!)
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun public_verifyError() {
        mockkStatic("net.aholbrook.paseto.crypto.EcdsaKt")
        every { ecdsaP384Verify(any(), any(), any()) } returns false

        try {
            val signed = PasetoV3.sign("abc".toByteArray(Charsets.UTF_8), keyV3Public.secretKey!!)
            shouldThrow<SignatureVerificationException> {
                PasetoV3.verify(signed, keyV3Public.publicKey)
            }
        } finally {
            unmockkAll()
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["v1", "v2"])
    fun local_rejectsIncorrectVersions(version: String) {
        val ex = shouldThrow<InvalidHeaderException> {
            PasetoV3.decrypt("$version.local.abc", keyV3Local)
        }
        ex.given shouldBe "$version.local."
        ex.expected shouldBe "v3.local."
        ex.token shouldBe "$version.local.abc"
    }

    @Test
    fun local_rejectsIncorrectPurpose() {
        val ex = shouldThrow<InvalidHeaderException> {
            PasetoV3.decrypt("v4.public.abc", keyV3Local)
        }
        ex.given shouldBe "v4.public."
        ex.expected shouldBe "v3.local."
        ex.token shouldBe "v4.public.abc"
    }

    @ParameterizedTest
    @ValueSource(strings = ["v1", "v2"])
    fun public_rejectsIncorrectVersions(version: String) {
        val ex = shouldThrow<InvalidHeaderException> {
            PasetoV3.verify("$version.public.abc", keyV3Public.publicKey)
        }
        ex.given shouldBe "$version.public."
        ex.expected shouldBe "v3.public."
        ex.token shouldBe "$version.public.abc"
    }

    @Test
    fun public_rejectsIncorrectPurpose() {
        val ex = shouldThrow<InvalidHeaderException> {
            PasetoV3.verify("v3.local.abc", keyV3Public.publicKey)
        }
        ex.given shouldBe "v3.local."
        ex.expected shouldBe "v3.public."
        ex.token shouldBe "v3.local.abc"
    }

    @Test
    fun local_rejectsPaddedBase64() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV3.decrypt("v3.local.YWJjCg==", keyV3Local)
        }
        ex.reason shouldBe TokenParseException.Reason.INVALID_BASE64
    }

    @Test
    fun public_rejectsPaddedBase64() {
        val ex = shouldThrow<TokenParseException> {
            PasetoV3.verify("v3.public.YWJjCg==", keyV3Public.publicKey)
        }
        ex.reason shouldBe TokenParseException.Reason.INVALID_BASE64
    }
}
