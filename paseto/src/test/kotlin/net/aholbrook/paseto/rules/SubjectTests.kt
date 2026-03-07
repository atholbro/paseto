package net.aholbrook.paseto.rules

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import net.aholbrook.paseto.exception.IncorrectSubjectException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.token
import org.junit.jupiter.api.Test

class SubjectTests {
    @Test
    fun validSubject() {
        val subject = Subject("abc")
        val token = token { this.subject = "abc" }

        shouldNotThrowAny {
            subject(token, Rule.Mode.DECODE, emptyMap())
        }
    }

    @Test
    fun missingSubject() {
        val subject = Subject("abc")
        val token = token { }

        val ex = shouldThrow<MissingClaimException> {
            subject(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "sub"
        ex.token shouldBeSameInstanceAs token
    }

    @Test
    fun emptySubjectIsConsideredMissing() {
        val subject = Subject("abc")
        val token = token { this.subject = "" }

        val ex = shouldThrow<MissingClaimException> {
            subject(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "sub"
        ex.token shouldBeSameInstanceAs token
    }

    @Test
    fun incorrectSubject() {
        val subject = Subject("abc")
        val token = token { this.subject = "def" }

        val ex = shouldThrow<IncorrectSubjectException> {
            subject(token, Rule.Mode.DECODE, emptyMap())
        }
        ex.claim shouldBe "sub"
        ex.rule shouldBeSameInstanceAs subject
        ex.token shouldBeSameInstanceAs token
    }
}
