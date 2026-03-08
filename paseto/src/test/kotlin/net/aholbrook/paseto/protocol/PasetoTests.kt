package net.aholbrook.paseto.protocol

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import net.aholbrook.paseto.exception.TokenParseException
import org.junit.jupiter.api.Test

class PasetoTests {
    @Test
    fun `split with incorrect token count -1`() {
        shouldThrow<TokenParseException> {
            split("a.b")
        }
    }

    @Test
    fun `split with incorrect token count +1`() {
        shouldThrow<TokenParseException> {
            split("a.b.c.d.e")
        }
    }

    @Test
    fun `extract footer empty string`() {
        extractFooter("v1.local.xyz") shouldBe ""
    }

    @Test
    fun `v1 secret key size is -1`() {
        Version.V1.asymmetricSecretKeySize shouldBe -1
    }
}
