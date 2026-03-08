package net.aholbrook.paseto.rules

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.exception.NotYetValidException
import net.aholbrook.paseto.exception.TokenIsNotValidUntilAfterExpiration
import net.aholbrook.paseto.token
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.ValueSource
import java.time.Clock
import java.time.Instant
import java.time.ZoneId

class NotBeforeTests {
    @ParameterizedTest
    @EnumSource(value = Rule.Mode::class)
    fun `requires claim`(mode: Rule.Mode) {
        val token = token { }
        val notBefore = NotBefore()

        val ex = shouldThrow<MissingClaimException> {
            notBefore(token, mode, emptyMap())
        }
        ex.claim shouldBe "nbf"
        ex.rule shouldBe null
    }

    @ParameterizedTest
    @ValueSource(longs = [0L, 1L])
    fun `when encoding if a expiresAt is provided then it must be after the notBefore time`(offset: Long) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            notBefore = clock.instant().plusSeconds(3600).plusSeconds(offset)
            expiresAt = clock.instant().plusSeconds(3600)
        }
        val notBefore = NotBefore(clock = clock)

        val ex = shouldThrow<TokenIsNotValidUntilAfterExpiration> {
            notBefore(token, Rule.Mode.ENCODE, emptyMap())
        }
        ex.rule shouldBe null
    }

    @Test
    fun `expiry after not before check only applies when expiry is non-null`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            notBefore = clock.instant().plusSeconds(3601)
            expiresAt = null
        }
        val notBefore = NotBefore(clock = clock)

        shouldNotThrowAny {
            notBefore(token, Rule.Mode.ENCODE, emptyMap())
        }
    }

    @Test
    fun `expiry after not before check only applies during encoding`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            notBefore = clock.instant().plusSeconds(3601)
            expiresAt = clock.instant().plusSeconds(3600)
        }
        val notBefore = NotBefore(clock = clock)

        val ex = shouldThrow<NotYetValidException> {
            notBefore(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.rule shouldBe null
    }

    @Test
    fun `encoding works with a valid token`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            notBefore = clock.instant().plusSeconds(10)
        }
        val notBefore = NotBefore(clock = clock)

        shouldNotThrowAny {
            notBefore(token, Rule.Mode.ENCODE, emptyMap())
        }
    }

    @Test
    fun `decoding works with a valid token`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant().minusSeconds(3600)
            notBefore = clock.instant().minusSeconds(3600)
        }
        val notBefore = NotBefore(clock = clock)

        shouldNotThrowAny {
            notBefore(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @ParameterizedTest(name = "decoding bounds check {0}")
    @ValueSource(longs = [-1L, 0L])
    fun `decoding bounds check`(offset: Long) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            notBefore = clock.instant().plusSeconds(offset)
        }
        val notBefore = NotBefore(clock = clock)

        shouldNotThrowAny {
            notBefore(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @Test
    fun `decoding bounds check - 1 second before`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            notBefore = clock.instant().plusSeconds(1)
        }
        val notBefore = NotBefore(clock = clock)

        val ex = shouldThrow<NotYetValidException> {
            notBefore(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.rule shouldBe null
    }
}
