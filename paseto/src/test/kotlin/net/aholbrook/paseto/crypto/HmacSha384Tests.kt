package net.aholbrook.paseto.crypto

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import net.aholbrook.paseto.exception.ByteArrayLengthException
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Test

class HmacSha384Tests {
    @Test
    fun hmacSha384_matchesTestVector() {
        val key: ByteArray = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val data: ByteArray = Hex.decode("4869205468657265")
        val expected = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"

        val hmac = hmacSha384(data, key)
        hmac shouldBe Hex.decode(expected)
    }

    @Test
    fun hmacSha384_emptyMessage() {
        shouldThrow<ByteArrayLengthException> {
            hmacSha384(ByteArray(0), ByteArray(20))
        }
    }

    @Test
    fun hmacSha384_emptyKey() {
        shouldThrow<ByteArrayLengthException> {
            hmacSha384(ByteArray(8), ByteArray(0))
        }
    }
}
