package net.aholbrook.paseto.rules

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import net.aholbrook.paseto.exception.ExpiredTokenException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.exception.TokenExpiresBeforeIssuedException
import net.aholbrook.paseto.token
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.ValueSource
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import kotlin.longArrayOf

class NotExpiredTests {
    @ParameterizedTest
    @EnumSource(value = Rule.Mode::class)
    fun `requires claim`(mode: Rule.Mode) {
        val token = token {
            expiresAt = null
        }
        val notExpired = NotExpired()

        val ex = shouldThrow<MissingClaimException> {
            notExpired(token, mode, emptyMap())
        }
        ex.claim shouldBe "exp"
    }

    @ParameterizedTest
    @ValueSource(longs = [0L, 1L])
    fun `when encoding if a issuedAt is provided then it must be before the expiresAt time`(offset: Long) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant().plusSeconds(offset)
            expiresAt = clock.instant()
        }
        val notExpired = NotExpired(clock = clock)

        shouldThrow<TokenExpiresBeforeIssuedException> {
            notExpired(token, Rule.Mode.ENCODE, emptyMap())
        }
    }

    @Test
    fun `expiry before issued check only applies when issuedAt is non-null`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = null
        }
        val notExpired = NotExpired(clock = clock)

        shouldNotThrowAny {
            notExpired(token, Rule.Mode.ENCODE, emptyMap())
        }
    }

    @Test
    fun `expiry before issued check only applies when issuedAt check only applies during encoding`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant()
            expiresAt = clock.instant().minusSeconds(3600)
        }
        val notExpired = NotExpired(clock = clock)

        shouldThrow<ExpiredTokenException> {
            notExpired(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @Test
    fun `encoding works with a valid token`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {}
        val notExpired = NotExpired(clock = clock)

        shouldNotThrowAny {
            notExpired(token, Rule.Mode.ENCODE, emptyMap())
        }
    }

    @Test
    fun `decoding works with a valid token`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) { }
        val notExpired = NotExpired(clock = clock)

        shouldNotThrowAny {
            notExpired(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @ParameterizedTest(name = "decoding bounds check {0}")
    @ValueSource(longs = [0L, 1L])
    fun `decoding bounds check`(offset: Long) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant()
            expiresAt = clock.instant().plusSeconds(offset)
        }
        val notExpired = NotExpired(clock = clock)

        shouldNotThrowAny {
            notExpired(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @Test
    fun `decoding bounds check - 1 second after`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant().minusSeconds(3600)
            expiresAt = clock.instant().minusSeconds(1)
        }
        val notExpired = NotExpired(clock = clock)

        shouldThrow<ExpiredTokenException> {
            notExpired(token, Rule.Mode.DECODE, emptyMap())
        }
    }
}
