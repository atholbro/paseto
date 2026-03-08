package net.aholbrook.paseto

import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import net.aholbrook.paseto.exception.CannotSignWithoutSecretKey
import net.aholbrook.paseto.exception.ImplicitAssertionsNotSupportedException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.exception.MultipleValidationErrorsException
import net.aholbrook.paseto.exception.TokenExpiresBeforeIssuedException
import net.aholbrook.paseto.exception.TokenIsNotValidUntilAfterExpiration
import net.aholbrook.paseto.protocol.Version
import net.aholbrook.paseto.protocol.key.KeyPair
import net.aholbrook.paseto.rules.CustomRule
import net.aholbrook.paseto.rules.IssuedInPast
import net.aholbrook.paseto.rules.NotBefore
import net.aholbrook.paseto.rules.NotExpired
import net.aholbrook.paseto.rules.rules
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.stream.Stream

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
        val token = token { }

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
        val token = token {
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
        val token = token {
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
        val token = token {
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
        val token = token {
            issuedAt = clock.instant().plusSeconds(1)
            expiresAt = clock.instant()
        }

        val ex = shouldThrow<MultipleValidationErrorsException> {
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

        val ex = shouldThrow<MultipleValidationErrorsException> {
            service.encode(token { })
        }
        ex.exceptions.map { it::class } shouldContain MissingClaimException::class
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `rejects a token that expires when it was issued`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose)
        val token = token {
            issuedAt = clock.instant()
            expiresAt = clock.instant()
        }

        val ex = shouldThrow<MultipleValidationErrorsException> {
            service.encode(token)
        }
        ex.exceptions.map { it::class } shouldContain TokenExpiresBeforeIssuedException::class
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `accepts a token that is issued after it becomes valid`(version: Version, purpose: Purpose) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val service = tokenService(version, purpose)
        val token = token {
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
        val token = token {
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
        val token = token {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(2)
            expiresAt = clock.instant().plusSeconds(1)
        }

        val ex = shouldThrow<MultipleValidationErrorsException> {
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
        val token = token {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(1)
            expiresAt = notBefore
        }

        val ex = shouldThrow<MultipleValidationErrorsException> {
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
        val token = token {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(1)
        }

        shouldNotThrow<TokenIsNotValidUntilAfterExpiration> {
            service.encode(token)
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
        val token = token {
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
        val token = token {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plusSeconds(3600)
        }

        val signed = signingService.encode(token)
        val decoded = shouldNotThrowAny {
            service.decode(signed, token.footer)
        }
        decoded shouldBe token
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun `can encode and decode a token with custom claims in both the token and footer`(
        version: Version,
        purpose: Purpose,
    ) {
        val token = token {
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
        val token = token {
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
