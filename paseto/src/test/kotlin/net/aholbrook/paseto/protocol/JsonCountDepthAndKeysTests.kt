package net.aholbrook.paseto.protocol

import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource

class JsonCountDepthAndKeysTests {
    @ParameterizedTest
    @CsvSource(
        value = [
            "{} | 1",
            "[] | 1",
            "{{{}}{}} | 3",
            "{{}{{}}} | 3",
            """{"a":1,"b":[1,2,{"c":true}]} | 3""",
            """{"text":"{[not-structure]}","items":[{"x":"\\\""}]} | 3""",
        ],
        delimiterString = " | ",
    )
    fun `valid payloads return expected depth`(payload: String, expectedDepth: Int) {
        jsonCountDepthAndKeys(payload).first shouldBe expectedDepth
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "}",
        "[]}",
        "{}]",
        "}[]",
        "][[[[[[]]]]]]",
        "[[[[[[]]]]]]]"
    ])
    fun `corrupt json return invalid depth`(json: String) {
        jsonCountDepthAndKeys(json).first shouldBe -1
    }

    @Test
    fun `deeply nested objects are handled`() {
        val depth = 128
        val payload = nestedObject(depth)

        jsonCountDepthAndKeys(payload).first shouldBe depth
    }

    @Test
    fun `deeply nested arrays are handled`() {
        val depth = 2000
        val payload = nestedArray(depth)

        jsonCountDepthAndKeys(payload).first shouldBe depth
    }

    private fun nestedObject(depth: Int): String {
        val prefix = "{\"x\":".repeat(depth)
        val suffix = "}".repeat(depth)
        return "$prefix 0 $suffix"
    }

    private fun nestedArray(depth: Int): String {
        val prefix = "[".repeat(depth)
        val suffix = "]".repeat(depth)
        return "$prefix 0 $suffix"
    }
}
