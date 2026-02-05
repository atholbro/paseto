package net.aholbrook.paseto

import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.junit.jupiter.api.Test
import kotlin.io.encoding.Base64

class Base64Tests {
    @Test
    fun `strictBase64UrlDecode rejects url encoding with padding`() {
        val invalid = Base64.UrlSafe.encode("has padding".toByteArray())

        Base64.UrlSafeNoPadding.decodeOrNull(invalid) shouldBe null
    }

    @Test
    fun `strictBase64UrlDecode accepts url encoding without padding`() {
        val invalid = Base64.UrlSafeNoPadding.encode("has padding".toByteArray())

        Base64.UrlSafeNoPadding.decodeOrNull(invalid) shouldNotBe null
    }
}
