package net.aholbrook.paseto.rules

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import net.aholbrook.paseto.exception.IncorrectAudienceException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.token
import org.junit.jupiter.api.Test

class ForAudienceTests {
    @Test
    fun validAudience() {
        val forAudience = ForAudience("abc")
        val token = token { audience = "abc" }

        shouldNotThrowAny {
            forAudience(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @Test
    fun missingAudience() {
        val forAudience = ForAudience("abc")
        val token = token { }

        val ex = shouldThrow<MissingClaimException> {
            forAudience(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "aud"
        ex.token shouldBeSameInstanceAs token
    }

    @Test
    fun emptyAudienceIsConsideredMissing() {
        val forAudience = ForAudience("abc")
        val token = token { audience = "" }

        val ex = shouldThrow<MissingClaimException> {
            forAudience(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "aud"
        ex.token shouldBeSameInstanceAs token
    }

    @Test
    fun incorrectAudience() {
        val forAudience = ForAudience("abc")
        val token = token { audience = "def" }

        val ex = shouldThrow<IncorrectAudienceException> {
            forAudience(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "aud"
        ex.rule shouldBeSameInstanceAs forAudience
        ex.token shouldBeSameInstanceAs token
    }
}
