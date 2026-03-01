package net.aholbrook.paseto.rules

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import net.aholbrook.paseto.exception.IncorrectIssuerException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.pasetoToken
import org.junit.jupiter.api.Test

class IssuedByTests {
    @Test
    fun validIssuedBy() {
        val issuedBy = IssuedBy("abc")
        val token = pasetoToken { issuer = "abc" }

        shouldNotThrowAny {
            issuedBy(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @Test
    fun missingIssuedBy() {
        val issuedBy = IssuedBy("abc")
        val token = pasetoToken { }

        val ex = shouldThrow<MissingClaimException> {
            issuedBy(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "iss"
        ex.token shouldBeSameInstanceAs token
    }

    @Test
    fun emptyIssuedByIsConsideredMissing() {
        val issuedBy = IssuedBy("abc")
        val token = pasetoToken { issuer = "" }

        val ex = shouldThrow<MissingClaimException> {
            issuedBy(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "iss"
        ex.token shouldBeSameInstanceAs token
    }

    @Test
    fun incorrectIssuedBy() {
        val issuedBy = IssuedBy("abc")
        val token = pasetoToken { issuer = "def" }

        val ex = shouldThrow<IncorrectIssuerException> {
            issuedBy(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "iss"
        ex.rule shouldBeSameInstanceAs issuedBy
        ex.token shouldBeSameInstanceAs token
    }
}
