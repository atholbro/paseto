package net.aholbrook.paseto.rules

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import net.aholbrook.paseto.exception.IssuedInFutureException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.pasetoToken
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class IssuedInPastTests {
    @Test
    fun defaults_validToken() {
        val issuedInPast = IssuedInPast()
        val token = pasetoToken {
            issuedAt = Instant.now().minusSeconds(3600L)
        }

        shouldNotThrowAny {
            issuedInPast(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @Test
    fun defaults_issuedInFuture() {
        val issuedInPast = IssuedInPast()
        val token = pasetoToken {
            issuedAt = Instant.now().plusSeconds(3600L)
        }

        val ex = shouldThrow<IssuedInFutureException> {
            issuedInPast(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "iat"
        ex.rule shouldBeSameInstanceAs issuedInPast
        ex.token shouldBeSameInstanceAs token
    }

    @Test
    fun defaults_missingIssuedAt() {
        val issuedInPast = IssuedInPast()
        val token = pasetoToken {
            issuedAt = null
            expiresAt = null
        }

        val ex = shouldThrow<MissingClaimException> {
            issuedInPast(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "iat"
        ex.token shouldBeSameInstanceAs token
    }

    @Test
    fun checkBounds_sameInstant() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)

        val issuedInPast = IssuedInPast(clock = clock)

        shouldNotThrowAny {
            issuedInPast(
                pasetoToken {
                    issuedAt = clock.instant()
                },
                Rule.Mode.DECODE,
                emptyMap(),
            )
        }
    }

    @Test
    fun checkBounds_1Second() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)

        val issuedInPast = IssuedInPast(clock = clock)

        shouldThrow<IssuedInFutureException> {
            issuedInPast(
                pasetoToken {
                    issuedAt = clock.instant().plusSeconds(1)
                },
                Rule.Mode.DECODE,
                emptyMap(),
            )
        }
    }

    @Test
    fun encode_missingIssuedAtThrows() {
        val issuedInPast = IssuedInPast()
        val token = pasetoToken {
            issuedAt = null
            expiresAt = null
        }

        val ex = shouldThrow<MissingClaimException> {
            issuedInPast(token, Rule.Mode.ENCODE, emptyMap())
        }
        ex.claim shouldBe "iat"
    }

    @Test
    fun encode_skipsIssuedInFutureCheck() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val issuedInPast = IssuedInPast(clock = clock)
        val token = pasetoToken {
            issuedAt = clock.instant().plusSeconds(3600)
        }

        shouldNotThrowAny {
            issuedInPast(token, Rule.Mode.ENCODE, emptyMap())
        }
    }
}
