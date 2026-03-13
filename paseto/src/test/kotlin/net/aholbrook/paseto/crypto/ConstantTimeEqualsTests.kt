package net.aholbrook.paseto.crypto

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.nio.charset.Charset

class ConstantTimeEqualsTests {
    @Test
    fun byteArray_constantTimeEquals_equalEmpty() {
        val a = byteArrayOf()
        val b = byteArrayOf()

        a.constantTimeEquals(b) shouldBe true
    }

    @Test
    fun byteArray_constantTimeEquals_equal() {
        val a = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        val b = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

        a.constantTimeEquals(b) shouldBe true
    }

    @Test
    fun byteArray_constantTimeEquals_notEqual() {
        val a = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        val b = byteArrayOf(10, 9, 8, 7, 6, 5, 4, 3, 2, 1)

        a.constantTimeEquals(b) shouldBe false
    }

    @Test
    fun byteArray_constantTimeEquals_differentSize() {
        val a = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        val b = byteArrayOf(10)

        a.constantTimeEquals(b) shouldBe false
    }

    @Test
    fun string_constantTimeEquals_empty() {
        "".constantTimeEquals("") shouldBe true
    }

    @Test
    fun string_constantTimeEquals_defaultIsUtf8() {
        "abc".constantTimeEquals("abc") shouldBe "abc".constantTimeEquals("abc", Charsets.UTF_8)
    }

    @ParameterizedTest
    @ValueSource(strings = ["UTF-8", "UTF-16"])
    fun string_constantTimeEquals_equal(charset: String) {
        val charset = Charset.forName(charset)
        val a = "paseto"
        val b = "paseto"

        a.constantTimeEquals(b, charset) shouldBe true
    }

    @ParameterizedTest
    @ValueSource(strings = ["UTF-8", "UTF-16"])
    fun string_constantTimeEquals_notEqual(charset: String) {
        val charset = Charset.forName(charset)
        val a = "paseto"
        val b = "jwt"

        a.constantTimeEquals(b, charset) shouldBe false
    }

    @ParameterizedTest
    @ValueSource(strings = ["UTF-8", "UTF-16"])
    fun string_constantTimeEquals_differentSize(charset: String) {
        val charset = Charset.forName(charset)
        val a = "paseto"
        val b = "p"

        a.constantTimeEquals(b, charset) shouldBe false
    }
}
