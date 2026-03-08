package net.aholbrook.paseto.rules

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import net.aholbrook.paseto.exception.IncorrectIssuerException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.token
import org.junit.jupiter.api.Test

class IssuedByTests {
    @Test
    fun validIssuedBy() {
        val issuedBy = IssuedBy("abc")
        val token = token { issuer = "abc" }

        shouldNotThrowAny {
            issuedBy(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @Test
    fun missingIssuedBy() {
        val issuedBy = IssuedBy("abc")
        val token = token { }

        val ex = shouldThrow<MissingClaimException> {
            issuedBy(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "iss"
        ex.token shouldBeSameInstanceAs token
        ex.rule shouldBe null
    }

    @Test
    fun emptyIssuedByIsConsideredMissing() {
        val issuedBy = IssuedBy("abc")
        val token = token { issuer = "" }

        val ex = shouldThrow<MissingClaimException> {
            issuedBy(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "iss"
        ex.token shouldBeSameInstanceAs token
        ex.rule shouldBe null
    }

    @Test
    fun incorrectIssuedBy() {
        val issuedBy = IssuedBy("abc")
        val token = token { issuer = "def" }

        val ex = shouldThrow<IncorrectIssuerException> {
            issuedBy(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "iss"
        ex.token shouldBeSameInstanceAs token
        ex.expected shouldBe "abc"
        ex.issuer shouldBe "def"
        ex.rule shouldBe null
    }
}
