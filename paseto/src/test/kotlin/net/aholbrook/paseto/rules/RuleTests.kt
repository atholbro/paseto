package net.aholbrook.paseto.rules

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import net.aholbrook.paseto.exception.IncorrectAudienceException
import net.aholbrook.paseto.exception.IncorrectIssuerException
import net.aholbrook.paseto.exception.IncorrectSubjectException
import net.aholbrook.paseto.exception.MultipleValidationErrorsException
import net.aholbrook.paseto.token
import org.junit.jupiter.api.Test

class RuleTests {
    @Test
    fun defaultRules() {
        val rules = rules { }

        rules.findByTypeOrNull<ForAudience>() shouldBe null
        rules.findByTypeOrNull<IdentifiedBy>() shouldBe null
        rules.findByTypeOrNull<IssuedBy>() shouldBe null
        rules.findByTypeOrNull<IssuedInPast>() shouldNotBe null
        rules.findByTypeOrNull<NotExpired>() shouldNotBe null
        rules.findByTypeOrNull<Subject>() shouldBe null
        rules.findByTypeOrNull<ValidAt>() shouldBe null
    }

    @Test
    fun verifyAll_happyPath() {
        val token = token {
            audience = "abc"
            issuer = "def"
        }

        val rules = rules {
            validAt = null
            issuedInPast = null
            forAudience = ForAudience("abc")
            issuedBy = IssuedBy("def")
        }

        val results = shouldNotThrowAny {
            rules.verifyAll(token, Rule.Mode.DECODE)
        }
        results.findByTypeOrNull<ForAudience>()?.second shouldBe RuleVerified
        results.findByTypeOrNull<IssuedBy>()?.second shouldBe RuleVerified
    }

    @Test
    fun verifyAll_claimContextIsUpdated() {
        val token = token {
            audience = "abc"
        }

        var customRuleVerified = false
        val forAudience = ForAudience("abc")
        val customRule = CustomRule { _, _, currentResults ->
            val (rule, result) = currentResults.findByTypeOrNull<ForAudience>()!!
            rule shouldBeSameInstanceAs forAudience
            result shouldBe RuleVerified
            customRuleVerified = true
        }
        val rules = rules {
            validAt = null
            issuedInPast = null
            this.forAudience = forAudience
            customRules.add(customRule)
        }

        shouldNotThrowAny {
            rules.verifyAll(token, Rule.Mode.DECODE)
        }
        customRuleVerified shouldBe true
    }

    @Test
    fun verifyAll_collectsAllRuleErrors() {
        val token = token {
            issuer = "x"
            audience = "y"
            subject = "z"
        }
        val rules = rules {
            validAt = null
            issuedInPast = null
            forAudience = ForAudience("abc")
            issuedBy = IssuedBy("def")
            subject = Subject("ghi")
        }

        val ex = shouldThrow<MultipleValidationErrorsException> {
            rules.verifyAll(token, Rule.Mode.DECODE)
        }

        val types = ex.exceptions.map { it::class }
        types shouldContain IncorrectAudienceException::class
        types shouldContain IncorrectIssuerException::class
        types shouldContain IncorrectSubjectException::class
    }

    @Test
    fun multipleRuleValidationExceptions_toString() {
        val token = token {}
        val rules = rules {
            validAt = null
            issuedInPast = null

            forAudience = ForAudience("abc")
            issuedBy = IssuedBy("def")
        }

        val ex = shouldThrow<MultipleValidationErrorsException> {
            rules.verifyAll(token, Rule.Mode.DECODE)
        }

        ex.toString() shouldBe """
            |net.aholbrook.paseto.exception.MultipleValidationErrorsException: Multiple verification errors:
            |  net.aholbrook.paseto.exception.MissingClaimException: Token is missing required claim aud.
            |  net.aholbrook.paseto.exception.MissingClaimException: Token is missing required claim iss.
        """.trimMargin()
    }

    @Test
    fun ruleSet_findByType_notFound() {
        val rules = rules { forAudience = null }
        rules.findByTypeOrNull<ForAudience>() shouldBe null
    }

    @Test
    fun resultMap_findByType_notFound() {
        val results = emptyMap<Rule, RuleResult>()
        results.findByTypeOrNull<ForAudience>() shouldBe null
    }

    @Test
    fun builder_copy() {
        val customRule1: CustomRule = { _, _, _ -> }
        val customRule2: CustomRule = { _, _, _ -> }
        val rules1 = rules {
            identifiedBy = IdentifiedBy("tk1")
            forAudience = ForAudience("abc")
            issuedBy = IssuedBy("def")
            subject = Subject("xyz")
            customRules.add(customRule1)
            customRules.add(customRule2)
        }

        rules(rules1) {
            identifiedBy shouldBeSameInstanceAs rules1.findByTypeOrNull<IdentifiedBy>()
            validAt shouldBeSameInstanceAs rules1.findByTypeOrNull<ValidAt>()
            forAudience shouldBeSameInstanceAs rules1.findByTypeOrNull<ForAudience>()
            issuedBy shouldBeSameInstanceAs rules1.findByTypeOrNull<IssuedBy>()
            issuedInPast shouldBeSameInstanceAs rules1.findByTypeOrNull<IssuedInPast>()
            subject shouldBeSameInstanceAs rules1.findByTypeOrNull<Subject>()
            customRules shouldContainExactly listOf(customRule1, customRule2)
        }
    }
}
