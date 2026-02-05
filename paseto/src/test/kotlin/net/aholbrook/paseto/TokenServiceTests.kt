package net.aholbrook.paseto

import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.serialization.json.Json
import net.aholbrook.paseto.exception.CannotSignWithoutSecretKey
import net.aholbrook.paseto.exception.ImplicitAssertionsNotSupportedException
import net.aholbrook.paseto.exception.InvalidFooterException
import net.aholbrook.paseto.exception.MultipleValidationExceptions
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.TokenExpiresBeforeIssuedException
import net.aholbrook.paseto.exception.TokenIsNotValidUntilAfterExpiration
import net.aholbrook.paseto.protocol.KeyPair
import net.aholbrook.paseto.protocol.Version
import net.aholbrook.paseto.rules.ValidAt
import net.aholbrook.paseto.rules.IssuedInPast
import net.aholbrook.paseto.rules.NotBefore
import net.aholbrook.paseto.rules.NotExpired
import net.aholbrook.paseto.rules.rules
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.stream.Stream
import kotlin.io.encoding.Base64

class TokenServiceTests {
    companion object {
        @JvmStatic
        fun allServiceConfigurations(): Stream<Arguments> =
            listOf(
                Pair(Version.V1, Purpose.Local { keyV1Local }),
                Pair(Version.V1, Purpose.Public { keyV1Public }),
                Pair(Version.V2, Purpose.Local { keyV2Local }),
                Pair(Version.V2, Purpose.Public { keyV2Public }),
                Pair(Version.V4, Purpose.Local { keyV4Local }),
                Pair(Version.V4, Purpose.Public { keyV4Public }),
            ).map {
                Arguments.of(it.first, it.second)
            }.stream()

        @JvmStatic
        fun publicServicesWithoutSecretKey(): Stream<Arguments> =
            listOf(
                Triple(
                    Version.V1,
                    Purpose.Public { KeyPair(null, keyV1Public.publicKey) },
                    Purpose.Public { keyV1Public },
                ),
                Triple(
                    Version.V2,
                    Purpose.Public { KeyPair(null, keyV2Public.publicKey) },
                    Purpose.Public { keyV2Public },
                ),
                Triple(
                    Version.V4,
                    Purpose.Public { KeyPair(null, keyV4Public.publicKey) },
                    Purpose.Public { keyV4Public },
                ),
            ).map {
                Arguments.of(it.first, it.second, it.third)
            }.stream()
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `v1 and v2 do not support implicit assertions`(version: Version, purpose: Purpose) {
        if (version != Version.V1 && version != Version.V2) { return }

        val service = tokenService(version, purpose)
        val token = pasetoToken {  }

        withClue("encode") {
            shouldThrow<ImplicitAssertionsNotSupportedException> {
                service.encode(token, "abc")
            }
        }
        withClue("decode") {
            shouldThrow<ImplicitAssertionsNotSupportedException> {
                service.decode("", implicitAssertion = "abc")
            }
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `all remaining versions support implicit assertions`(version: Version, purpose: Purpose) {
        if (version == Version.V1 || version == Version.V2) { return }

        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
        }
        var encoded = ""

        withClue("encode") {
            shouldNotThrow<ImplicitAssertionsNotSupportedException> {
                encoded = service.encode(token, "abc")
            }
        }
        withClue("decode") {
            shouldNotThrow<ImplicitAssertionsNotSupportedException> {
                service.decode(encoded, implicitAssertion = "abc")
            }
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `null implicit assertion does not error regardless of version`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofMinutes(1))
        }

        var encoded = ""
        withClue("encode") {
            shouldNotThrow<ImplicitAssertionsNotSupportedException> {
                encoded = service.encode(token, implicitAssertion = null)
            }
        }
        withClue("decode") {
            shouldNotThrow<ImplicitAssertionsNotSupportedException> {
                service.decode(encoded, implicitAssertion = null)
            }
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `empty implicit assertion does not error regardless of version`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofMinutes(1))
        }

        var encoded = ""
        withClue("encode") {
            shouldNotThrow<ImplicitAssertionsNotSupportedException> {
                encoded = service.encode(token, implicitAssertion = null)
            }
        }
        withClue("decode") {
            shouldNotThrow<ImplicitAssertionsNotSupportedException> {
                service.decode(encoded, implicitAssertion = null)
            }
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `allows tokens without expiration set`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                notExpired = null
                issuedInPast = IssuedInPast(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = null
        }

        val encrypted = service.encode(token, null)
        val decrypted = service.decode(encrypted, null, null)

        decrypted.issuedAt shouldBe token.issuedAt
        decrypted.expiresAt shouldBe null
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `rejects a token that expires before it was issued`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = clock.instant().plusSeconds(1)
            expiresAt = clock.instant()
        }

        val ex = shouldThrow<MultipleValidationExceptions> {
            service.encode(token, null)
        }
        ex.exceptions.map { it::class } shouldContain TokenExpiresBeforeIssuedException::class
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `rejects a token that expires when it was issued`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant()
        }

        val ex = shouldThrow<MultipleValidationExceptions> {
            service.encode(token, null)
        }
        ex.exceptions.map { it::class } shouldContain TokenExpiresBeforeIssuedException::class
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `accepts a token that is issued after it becomes valid`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = clock.instant()
            notBefore = clock.instant().minusSeconds(1)
            expiresAt = clock.instant().plusSeconds(1)
        }

        shouldNotThrowAny {
            service.encode(token, null)
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `accepts a token that is issued at the same time it becomes valid`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = clock.instant()
            notBefore = issuedAt
            expiresAt = clock.instant().plusSeconds(1)
        }

        shouldNotThrowAny {
            service.encode(token, null)
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `rejects a token that expires before it becomes valid`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                notBefore = NotBefore(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(2)
            expiresAt = clock.instant().plusSeconds(1)
        }

        val ex = shouldThrow<MultipleValidationExceptions> {
            service.encode(token, null)
        }
        ex.exceptions.map { it::class } shouldContain TokenIsNotValidUntilAfterExpiration::class
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `rejects a token that expires as it becomes valid`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                notBefore = NotBefore(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(1)
            expiresAt = notBefore
        }

        val ex = shouldThrow<MultipleValidationExceptions> {
            service.encode(token, null)
        }
        ex.exceptions.map { it::class } shouldContain TokenIsNotValidUntilAfterExpiration::class
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `allows a token that has notBefore without expiration`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                notExpired = null
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(1)
        }

        shouldNotThrow<TokenIsNotValidUntilAfterExpiration> {
            service.encode(token, null)
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `errors on footer mismatch`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
            footer = pasetoFooter("test footer value")
        }

        val encoded = service.encode(token, null)
        shouldThrow<InvalidFooterException> {
            service.decode(encoded, pasetoFooter("wrong"))
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer reverts to string if not a json object`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
            footer = pasetoFooter("[1,2,3]")
        }

        val encoded = service.encode(token, null)
        val decoded = service.decode(encoded, token.footer)
        decoded.footer shouldBe pasetoFooter("[1,2,3]")
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer decode handles invalid json`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
            footer = pasetoFooter("{")
        }

        val encoded = service.encode(token, null)
        val decoded = service.decode(encoded, token.footer)
        decoded.footer shouldBe pasetoFooter("{")
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `can decode a string footer without decoding the token`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer = pasetoFooter("just a string")
        }

        val encoded = service.encode(token, null)
        val taintedFooter = service.insecureGetFooter(encoded)

        (taintedFooter as TaintedStringFooter).value shouldBe "just a string"

        taintedFooter shouldBe token.footer.taint()
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `can decode a claim footer without decoding the token`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer = pasetoFooter {
                keyId = "key-3"
                wrappedKey = "invalid"
                claims = claimObject {
                    put("custom", "also works?")
                }
            }
        }

        val encoded = service.encode(token, null)
        val taintedFooter = service.insecureGetFooter(encoded)

        with (taintedFooter as TaintedClaimFooter) {
            keyId shouldBe "key-3"
            wrappedKey shouldBe "invalid"
            claims["custom"]?.stringOrNull shouldBe "also works?"
        }

        taintedFooter shouldBe token.footer.taint()
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer verification works for string footer`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer = pasetoFooter("just a string")
        }

        val encoded = service.encode(token, null)
        val decoded = service.decode(encoded, token.footer)
        decoded.footer shouldBe token.footer
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer verification works for claim footer`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer = pasetoFooter {
                keyId = "key-3"
                wrappedKey = "invalid"
                claims = claimObject {
                    put("custom", "also works?")
                }
            }
        }

        val encoded = service.encode(token, null)
        val decoded = service.decode(encoded, token.footer)
        decoded.footer shouldBe token.footer
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer verification catches errors in string footers`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer = pasetoFooter("just a string")
        }
        val expectedFooter = pasetoFooter("not the string")

        val encoded = service.encode(token, null)
        shouldThrow<InvalidFooterException> {
            service.decode(encoded, expectedFooter)
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer verification catches errors in claim footers`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer = pasetoFooter {
                keyId = "key-3"
                wrappedKey = "invalid"
                claims = claimObject {
                    put("custom", "also works?")
                }
            }
        }
        val expectedFooter = pasetoFooter { }

        val encoded = service.encode(token, null)
        shouldThrow<InvalidFooterException> {
            service.decode(encoded, expectedFooter)
        }
    }

    @ParameterizedTest
    @MethodSource("publicServicesWithoutSecretKey")
    fun `cannot sign without a secret key`(version: Version, purpose: Purpose, signingPurpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules = rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
        }

        shouldThrow<CannotSignWithoutSecretKey> {
            service.encode(token, null)
        }
    }

    @ParameterizedTest
    @MethodSource("publicServicesWithoutSecretKey")
    fun `can verify without a secret key`(version: Version, purpose: Purpose, signingPurpose: Purpose) {
        val service = tokenService(version, purpose)
        val signingService = tokenService(version, signingPurpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plusSeconds(3600)
        }

        val signed = signingService.encode(token, null)
        val decoded = shouldNotThrowAny {
            service.decode(signed, token.footer)
        }
        decoded shouldBe token
    }

    @Test
    fun decodeFooter_catchesIllegalArgumentException() {
        val json = mockk<Json>()
        every {
            json.decodeFromString<ClaimFooter>(any(), any())
        } throws IllegalArgumentException()

        try {
            shouldNotThrow<IllegalArgumentException> {
                (json.decodeFooter("abc") as StringFooter).value shouldBe "abc"
            }
        } finally {
            unmockkAll()
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun decodeFooter_paddedBase64Fails(version: Version, purpose: Purpose) {
        val invalid = Base64.UrlSafe.encode("has padding".toByteArray())
        val purposeStr = when (purpose) {
            is Purpose.Local -> "local"
            is Purpose.Public -> "public"
        }
        val token = "${version.toString().lowercase()}.$purposeStr.a.$invalid"
        val service = tokenService(version, purpose)

        val ex = shouldThrow<PasetoParseException> {
            service.decode(token) shouldBe null
        }
        ex.reason shouldBe PasetoParseException.Reason.INVALID_BASE64
    }

    @Test
    fun insecureGetFooter_paddedBase64Fails() {
        val invalid = Base64.UrlSafe.encode("has padding".toByteArray())
        val token = "v4.local.a.$invalid"
        val service = tokenService(Version.V4, Purpose.Local { keyV4Local })

        val ex = shouldThrow<PasetoParseException> {
            service.insecureGetFooter(token) shouldBe null
        }
        ex.reason shouldBe PasetoParseException.Reason.INVALID_BASE64
    }
}
