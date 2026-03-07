package net.aholbrook.paseto.protocol

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import net.aholbrook.paseto.exception.PasetoParseException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class PasetoTests {
    @Test
    fun `split with incorrect token count -1`() {
        shouldThrow<PasetoParseException> {
            split("a.b")
        }
    }

    @Test
    fun `split with incorrect token count +1`() {
        shouldThrow<PasetoParseException> {
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
