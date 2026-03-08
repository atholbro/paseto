package net.aholbrook.paseto.rules

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import net.aholbrook.paseto.exception.ExpiredTokenException
import net.aholbrook.paseto.exception.IssuedInFutureException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.exception.NotYetValidException
import net.aholbrook.paseto.exception.TokenExpiresBeforeIssuedException
import net.aholbrook.paseto.exception.TokenIsNotValidUntilAfterExpiration
import net.aholbrook.paseto.token
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.ValueSource
import java.time.Clock
import java.time.Instant
import java.time.ZoneId

class ValidAtTests {
    @ParameterizedTest
    @EnumSource(value = Rule.Mode::class)
    fun `requires iat claim`(mode: Rule.Mode) {
        val token = token {
            issuedAt = null
            notBefore = Instant.now()
        }
        val validAt = ValidAt()

        val ex = shouldThrow<MissingClaimException> {
            validAt(token, mode, emptyMap())
        }
        ex.claim shouldBe "iat"
        ex.rule shouldBe null
    }

    @ParameterizedTest
    @EnumSource(value = Rule.Mode::class)
    fun `requires nbf claim`(mode: Rule.Mode) {
        val token = token { }
        val validAt = ValidAt()

        val ex = shouldThrow<MissingClaimException> {
            validAt(token, mode, emptyMap())
        }
        ex.claim shouldBe "nbf"
        ex.rule shouldBe null
    }

    @ParameterizedTest
    @EnumSource(value = Rule.Mode::class)
    fun `requires exp claim`(mode: Rule.Mode) {
        val token = token {
            notBefore = Instant.now()
            expiresAt = null
        }
        val validAt = ValidAt()

        val ex = shouldThrow<MissingClaimException> {
            validAt(token, mode, emptyMap())
        }
        ex.claim shouldBe "exp"
        ex.rule shouldBe null
    }

    @ParameterizedTest
    @ValueSource(longs = [-1L, 0L, 1L])
    fun `when encoding issuedAt is less than or equal to expiresAt`(offset: Long) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant().plusSeconds(offset)
            notBefore = clock.instant().minusSeconds(1)
            expiresAt = clock.instant()
        }
        val validAt = ValidAt(clock = clock)

        if (offset > 0) {
            val ex = shouldThrow<TokenExpiresBeforeIssuedException> {
                validAt(token, Rule.Mode.ENCODE, emptyMap())
            }
            ex.rule shouldBe null
        } else {
            shouldNotThrowAny {
                validAt(token, Rule.Mode.ENCODE, emptyMap())
            }
        }
    }

    @Test
    fun `issued after expiry check only applies during encoding`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant()
            notBefore = clock.instant().minusSeconds(1)
            expiresAt = clock.instant().minusSeconds(1)
        }
        val validAt = ValidAt(clock = clock)

        val ex = shouldThrow<ExpiredTokenException> {
            validAt(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.rule shouldBe null
    }

    @ParameterizedTest
    @ValueSource(longs = [-1L, 0L, 1L])
    fun `when encoding notBefore is less than expiresAt`(offset: Long) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant().minusSeconds(3600)
            notBefore = clock.instant().plusSeconds(offset)
            expiresAt = clock.instant()
        }
        val validAt = ValidAt(clock = clock)

        if (offset >= 0) {
            val ex = shouldThrow<TokenIsNotValidUntilAfterExpiration> {
                validAt(token, Rule.Mode.ENCODE, emptyMap())
            }
            ex.rule shouldBe null
        } else {
            shouldNotThrowAny {
                validAt(token, Rule.Mode.ENCODE, emptyMap())
            }
        }
    }

    @Test
    fun `expiry after not before check only applies during encoding`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(3601)
            expiresAt = clock.instant().plusSeconds(3600)
        }
        val validAt = ValidAt(clock = clock)

        val ex = shouldThrow<NotYetValidException> {
            validAt(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.rule shouldBe null
    }

    @ParameterizedTest
    @EnumSource(value = Rule.Mode::class)
    fun `works with a valid token`(mode: Rule.Mode) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            notBefore = clock.instant()
        }
        val validAt = ValidAt(clock = clock)

        shouldNotThrowAny {
            validAt(token, mode, emptyMap())
        }
    }

    @ParameterizedTest(name = "decoding bounds check {0}")
    @ValueSource(longs = [-1L, 0L, 1L])
    fun `decoding exp bounds check`(offset: Long) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant()
            notBefore = clock.instant()
            expiresAt = clock.instant().plusSeconds(offset)
        }
        val validAt = ValidAt(clock = clock)

        if (offset >= 0) {
            shouldNotThrowAny {
                validAt(token, Rule.Mode.DECODE, emptyMap())
            }
        } else {
            val ex = shouldThrow<ExpiredTokenException> {
                validAt(token, Rule.Mode.DECODE, emptyMap())
            }
            ex.rule shouldBe null
        }
    }

    @ParameterizedTest(name = "decoding bounds check {0}")
    @ValueSource(longs = [-1L, 0L, 1L])
    fun `decoding iat bounds check`(offset: Long) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant().plusSeconds(offset)
            notBefore = clock.instant().plusSeconds(offset)
            expiresAt = clock.instant().plusSeconds(3600)
        }
        val validAt = ValidAt(clock = clock)

        if (offset <= 0) {
            shouldNotThrowAny {
                validAt(token, Rule.Mode.DECODE, emptyMap())
            }
        } else {
            val ex = shouldThrow<IssuedInFutureException> {
                validAt(token, Rule.Mode.DECODE, emptyMap())
            }
            ex.rule shouldBe null
        }
    }

    @ParameterizedTest(name = "decoding bounds check {0}")
    @ValueSource(longs = [-1L, 0L, 1L])
    fun `decoding nbf bounds check`(offset: Long) {
        val clock = Clock.fixed(Instant.EPOCH, ZoneId.of("UTC"))
        val token = token(clock) {
            issuedAt = clock.instant()
            notBefore = clock.instant().plusSeconds(offset)
            expiresAt = clock.instant().plusSeconds(3600)
        }
        val validAt = ValidAt(clock = clock)

        if (offset <= 0) {
            shouldNotThrowAny {
                validAt(token, Rule.Mode.DECODE, emptyMap())
            }
        } else {
            val ex = shouldThrow<NotYetValidException> {
                validAt(token, Rule.Mode.DECODE, emptyMap())
            }
            ex.rule shouldBe null
        }
    }
}
