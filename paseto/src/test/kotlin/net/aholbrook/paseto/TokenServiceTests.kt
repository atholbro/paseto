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
import net.aholbrook.paseto.exception.FooterExceedsMaxDepthException
import net.aholbrook.paseto.exception.FooterExceedsMaxKeysException
import net.aholbrook.paseto.exception.FooterExceedsMaxLengthException
import net.aholbrook.paseto.exception.FooterJsonParseException
import net.aholbrook.paseto.exception.GenericInvalidFooterException
import net.aholbrook.paseto.exception.ImplicitAssertionsNotSupportedException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.exception.MultipleValidationExceptions
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.exception.TokenExpiresBeforeIssuedException
import net.aholbrook.paseto.exception.TokenIsNotValidUntilAfterExpiration
import net.aholbrook.paseto.protocol.KeyPair
import net.aholbrook.paseto.protocol.Version
import net.aholbrook.paseto.rules.CustomRule
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
        fun allServiceConfigurations(): Stream<Arguments> = listOf(
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
        fun publicServicesWithoutSecretKey(): Stream<Arguments> = listOf(
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
        if (version != Version.V1 && version != Version.V2) {
            return
        }

        val service = tokenService(version, purpose)
        val token = pasetoToken { }

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
        if (version == Version.V1 || version == Version.V2) {
            return
        }

        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
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
    fun `empty implicit assertion does not error regardless of version`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
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
                encoded = service.encode(token, implicitAssertion = "")
            }
        }
        withClue("decode") {
            shouldNotThrow<ImplicitAssertionsNotSupportedException> {
                service.decode(encoded, implicitAssertion = "")
            }
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `allows tokens without expiration set`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
                notExpired = null
                issuedInPast = IssuedInPast(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = null
        }

        val encrypted = service.encode(token, "")
        val decrypted = service.decode(encrypted, StringFooter(""), "")

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
            service.encode(token, "")
        }
        ex.exceptions.map { it::class } shouldContain TokenExpiresBeforeIssuedException::class
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `can apply externally built rules in token service builder`(version: Version, purpose: Purpose) {
        val rules = rules {
            customRules += CustomRule { token, _, _ ->
                throw MissingClaimException("external", token)
            }
        }
        val service = tokenService(version, purpose) {
            rules(rules)
        }

        val ex = shouldThrow<MultipleValidationExceptions> {
            service.encode(pasetoToken { })
        }
        ex.exceptions.map { it::class } shouldContain MissingClaimException::class
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
            service.encode(token)
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
            service.encode(token)
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
            service.encode(token)
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `rejects a token that expires before it becomes valid`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
                notBefore = NotBefore(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(2)
            expiresAt = clock.instant().plusSeconds(1)
        }

        val ex = shouldThrow<MultipleValidationExceptions> {
            service.encode(token)
        }
        ex.exceptions.map { it::class } shouldContain TokenIsNotValidUntilAfterExpiration::class
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `rejects a token that expires as it becomes valid`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
                notBefore = NotBefore(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(1)
            expiresAt = notBefore
        }

        val ex = shouldThrow<MultipleValidationExceptions> {
            service.encode(token)
        }
        ex.exceptions.map { it::class } shouldContain TokenIsNotValidUntilAfterExpiration::class
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `allows a token that has notBefore without expiration`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
                notExpired = null
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(1)
        }

        shouldNotThrow<TokenIsNotValidUntilAfterExpiration> {
            service.encode(token)
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `errors on footer mismatch`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
            footer("test footer value")
        }

        val encoded = service.encode(token)
        shouldThrow<GenericInvalidFooterException> {
            service.decode(encoded, footer("wrong"))
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer parse mode auto reverts to string if not a json object`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
            footerOptions {
                parseMode = FooterParseMode.AUTO
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
            footer("[1,2,3]")
        }

        val encoded = service.encode(token)
        val decoded = service.decode(encoded, token.footer)
        decoded.footer shouldBe footer("[1,2,3]")
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer parse mode auto handles invalid json`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
            footer("{")
        }

        val encoded = service.encode(token)
        val decoded = service.decode(encoded, token.footer)
        decoded.footer shouldBe footer("{")
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `footer parse mode auto validation rejects footer that exceeds max length`(version: Version, purpose: Purpose) {
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("123456")
        }
        val encoded = tokenService(version, purpose).encode(token)
        val service = tokenService(version, purpose) {
            footerOptions {
                maxLength = 5
            }
        }

        val ex = shouldThrow<FooterExceedsMaxLengthException> {
            service.decode(encoded, token.footer)
        }
        ex.length shouldBe 6
        ex.max shouldBe 5
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `footer parse mode auto validation rejects footer that exceeds max depth`(version: Version, purpose: Purpose) {
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("{\"a\":{\"b\":1}}")
        }
        val encoded = tokenService(version, purpose).encode(token)
        val service = tokenService(version, purpose) {
            footerOptions {
                maxDepth = 1
            }
        }

        val ex = shouldThrow<FooterExceedsMaxDepthException> {
            service.decode(encoded, token.footer)
        }
        ex.depth shouldBe 2
        ex.max shouldBe 1
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `footer parse mode auto validation rejects footer that exceeds max keys`(version: Version, purpose: Purpose) {
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("{\"a\":1,\"b\":2}")
        }
        val encoded = tokenService(version, purpose).encode(token)
        val service = tokenService(version, purpose) {
            footerOptions {
                maxKeys = 1
            }
        }

        val ex = shouldThrow<FooterExceedsMaxKeysException> {
            service.decode(encoded, token.footer)
        }
        ex.keys shouldBe 2
        ex.max shouldBe 1
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `parse mode auto can decode a string footer without decoding the token`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("just a string")
        }

        val encoded = service.encode(token)
        val taintedFooter = service.insecureGetFooter(encoded)

        (taintedFooter as TaintedStringFooter).value shouldBe "just a string"

        taintedFooter shouldBe token.footer.taint()
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `parse mode auto can decode a claim footer without decoding the token`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer {
                keyId = "key-3"
                wrappedKey = "invalid"
                claims {
                    put("custom", "also works?")
                }
            }
        }

        val encoded = service.encode(token)
        val taintedFooter = service.insecureGetFooter(encoded)

        with(taintedFooter as TaintedClaimFooter) {
            keyId shouldBe "key-3"
            wrappedKey shouldBe "invalid"
            claims["custom"]?.stringOrNull shouldBe "also works?"
        }

        taintedFooter shouldBe token.footer.taint()
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `parse mode auto only applies validations to object-like footer`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose) {
            footerOptions {
                parseMode = FooterParseMode.AUTO
                maxKeys = 2
            }
        }
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("::::")
        }

        val encoded = service.encode(token)
        val decoded = service.decode(encoded)
        decoded.footer shouldBe token.footer
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer parse mode claims errors on invalid json`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
            footerOptions {
                parseMode = FooterParseMode.CLAIMS
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
            footer("{")
        }

        val encoded = service.encode(token)
        shouldThrow<FooterJsonParseException> {
            service.decode(encoded, token.footer)
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `footer parse mode claims validation rejects footer that exceeds max length`(version: Version, purpose: Purpose) {
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("123456")
        }
        val encoded = tokenService(version, purpose).encode(token)
        val service = tokenService(version, purpose) {
            footerOptions {
                parseMode = FooterParseMode.CLAIMS
                maxLength = 5
            }
        }

        val ex = shouldThrow<FooterExceedsMaxLengthException> {
            service.decode(encoded, token.footer)
        }
        ex.length shouldBe 6
        ex.max shouldBe 5
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `footer parse mode claims validation rejects footer that exceeds max depth`(version: Version, purpose: Purpose) {
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("{\"a\":{\"b\":1}}")
        }
        val encoded = tokenService(version, purpose).encode(token)
        val service = tokenService(version, purpose) {
            footerOptions {
                parseMode = FooterParseMode.CLAIMS
                maxDepth = 1
            }
        }

        val ex = shouldThrow<FooterExceedsMaxDepthException> {
            service.decode(encoded, token.footer)
        }
        ex.depth shouldBe 2
        ex.max shouldBe 1
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `footer parse mode claims validation rejects footer that exceeds max keys`(version: Version, purpose: Purpose) {
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("{\"a\":1,\"b\":2}")
        }
        val encoded = tokenService(version, purpose).encode(token)
        val service = tokenService(version, purpose) {
            footerOptions {
                parseMode = FooterParseMode.CLAIMS
                maxKeys = 1
            }
        }

        val ex = shouldThrow<FooterExceedsMaxKeysException> {
            service.decode(encoded, token.footer)
        }
        ex.keys shouldBe 2
        ex.max shouldBe 1
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer parse mode string ignores invalid json`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
            footerOptions {
                parseMode = FooterParseMode.STRING
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
            footer("{")
        }

        val encoded = service.encode(token)
        val decoded = service.decode(encoded, token.footer)
        decoded.footer shouldBe footer("{")
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `footer parse mode string validation rejects footer that exceeds max length`(version: Version, purpose: Purpose) {
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("123456")
        }
        val encoded = tokenService(version, purpose).encode(token)
        val service = tokenService(version, purpose) {
            footerOptions {
                parseMode = FooterParseMode.STRING
                maxLength = 5
            }
        }

        val ex = shouldThrow<FooterExceedsMaxLengthException> {
            service.decode(encoded, token.footer)
        }
        ex.length shouldBe 6
        ex.max shouldBe 5
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `footer parse mode string ignores max depth`(version: Version, purpose: Purpose) {
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("{\"a\":{\"b\":1}}")
        }
        val encoded = tokenService(version, purpose).encode(token)
        val service = tokenService(version, purpose) {
            footerOptions {
                parseMode = FooterParseMode.STRING
                maxDepth = 1
            }
        }

        val decoded = service.decode(encoded, token.footer)
        decoded.footer shouldBe token.footer
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `footer parse mode string ignores max keys`(version: Version, purpose: Purpose) {
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("{\"a\":1,\"b\":2}")
        }
        val encoded = tokenService(version, purpose).encode(token)
        val service = tokenService(version, purpose) {
            footerOptions {
                parseMode = FooterParseMode.STRING
                maxKeys = 1
            }
        }

        val decoded = service.decode(encoded, token.footer)
        decoded.footer shouldBe token.footer
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer verification does not apply if argument is not given`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("just a string")
        }

        val encoded = service.encode(token)
        shouldNotThrow<GenericInvalidFooterException> {
            service.decode(encoded)
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer verification applies for empty string (no footer)`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("just a string")
        }

        val encoded = service.encode(token)
        shouldThrow<GenericInvalidFooterException> {
            service.decode(encoded, footer(""))
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `token footer verification works for string footer`(version: Version, purpose: Purpose) {
        val service = tokenService(version, purpose)
        val token = pasetoToken {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer("just a string")
        }

        val encoded = service.encode(token)
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
            footer {
                keyId = "key-3"
                wrappedKey = "invalid"
                claims {
                    put("custom", "also works?")
                }
            }
        }

        val encoded = service.encode(token)
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
            footer("just a string")
        }
        val expectedFooter = footer("not the string")

        val encoded = service.encode(token)
        shouldThrow<GenericInvalidFooterException> {
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
            footer {
                keyId = "key-3"
                wrappedKey = "invalid"
                claims {
                    put("custom", "also works?")
                }
            }
        }
        val expectedFooter = footer { }

        val encoded = service.encode(token)
        shouldThrow<GenericInvalidFooterException> {
            service.decode(encoded, expectedFooter)
        }
    }

    @ParameterizedTest
    @MethodSource("publicServicesWithoutSecretKey")
    @Suppress("unused_parameter", "UnusedParameter")
    fun `cannot sign without a secret key`(version: Version, purpose: Purpose, signingPurpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose) {
            rules {
                issuedInPast = IssuedInPast(clock = clock)
                notExpired = NotExpired(clock = clock)
            }
        }
        val token = pasetoToken {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plus(Duration.ofHours(1))
        }

        shouldThrow<CannotSignWithoutSecretKey> {
            service.encode(token)
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

        val signed = signingService.encode(token)
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
                (json.decodeFooter(FooterOptions(), "abc") as StringFooter).value shouldBe "abc"
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

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `can encode and decode a token with custom claims in both the token and footer`(
        version: Version,
        purpose: Purpose,
    ) {
        val token = pasetoToken {
            claims {
                put("pi", Math.PI)
            }
            footer {
                keyId = "key-1"
                claims {
                    put("e", Math.E)
                }
            }
        }
        val service = tokenService(version, purpose)

        val encoded = service.encode(token)
        val decoded = service.decode(encoded, token.footer)

        decoded shouldBe token
        decoded.claims["pi"]?.doubleOrNull shouldBe Math.PI
        val footer = decoded.footer as ClaimFooter
        footer.claims["e"]?.doubleOrNull shouldBe Math.E
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `can pass a footer into the token builder`(version: Version, purpose: Purpose) {
        val footer = footer {
            keyId = "key-1"
            claims {
                put("e", Math.E)
            }
        }
        val token = pasetoToken {
            claims {
                put("pi", Math.PI)
            }
            footer(footer)
        }
        val service = tokenService(version, purpose)

        val encoded = service.encode(token)
        val decoded = service.decode(encoded, token.footer)

        decoded shouldBe token
        decoded.claims["pi"]?.doubleOrNull shouldBe Math.PI
        val decodedFooter = decoded.footer as ClaimFooter
        decodedFooter shouldBe footer
        decodedFooter.claims["e"]?.doubleOrNull shouldBe Math.E
    }
}
