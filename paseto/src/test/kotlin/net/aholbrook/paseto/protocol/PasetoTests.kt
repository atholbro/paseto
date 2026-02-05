package net.aholbrook.paseto.protocol

import io.kotest.assertions.throwables.shouldThrow
import net.aholbrook.paseto.exception.PasetoParseException
import org.junit.jupiter.api.Test

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
}
