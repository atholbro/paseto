package net.aholbrook.paseto.crypto

import io.kotest.matchers.shouldNotBe
import org.junit.jupiter.api.Test

class RngTests {
    @Test
    fun randomBytes_generatesDifferentResults() {
        val r1 = randomBytes(24)
        val r2 = randomBytes(24)
        r1 shouldNotBe r2
    }

    @Test
    fun generateNonce_generatesDifferentResults() {
        val r1 = generateNonce(32)
        val r2 = generateNonce(32)
        r1 shouldNotBe r2
    }
}
