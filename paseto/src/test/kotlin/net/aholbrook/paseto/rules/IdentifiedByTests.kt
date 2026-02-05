package net.aholbrook.paseto.rules

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import net.aholbrook.paseto.exception.IncorrectTokenIdException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.pasetoToken
import org.junit.jupiter.api.Test

class IdentifiedByTests {
    @Test
    fun validTokenId() {
        val identifiedBy = IdentifiedBy("abc")
        val token = pasetoToken { tokenId = "abc" }

        shouldNotThrowAny {
            identifiedBy(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @Test
    fun missingTokenId() {
        val identifiedBy = IdentifiedBy("abc")
        val token = pasetoToken {  }

        val ex = shouldThrow<MissingClaimException> {
            identifiedBy(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "jti"
        ex.token shouldBeSameInstanceAs token
    }

    @Test
    fun emptyTokenIdIsConsideredMissing() {
        val identifiedBy = IdentifiedBy("abc")
        val token = pasetoToken { tokenId = "" }

        val ex = shouldThrow<MissingClaimException> {
            identifiedBy(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "jti"
        ex.token shouldBeSameInstanceAs token
    }

    @Test
    fun incorrectTokenId() {
        val identifiedBy = IdentifiedBy("abc")
        val token = pasetoToken { tokenId = "def" }

        val ex = shouldThrow<IncorrectTokenIdException> {
            identifiedBy(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "jti"
        ex.rule shouldBeSameInstanceAs identifiedBy
        ex.token shouldBeSameInstanceAs token
    }
}
