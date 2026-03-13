package net.aholbrook.paseto.crypto

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import net.aholbrook.paseto.exception.ByteArrayLengthException
import org.junit.jupiter.api.Test

class HkdfTests {
    @Test
    fun hkdfExtractAndExpand_shortSalt() {
        shouldThrow<ByteArrayLengthException> {
            hkdfExtractAndExpand(ByteArray(HKDF_SALT_LEN - 1), ByteArray(20), ByteArray(8))
        }
    }

    @Test
    fun hkdfExtractAndExpand_longSalt() {
        shouldThrow<ByteArrayLengthException> {
            hkdfExtractAndExpand(ByteArray(HKDF_SALT_LEN + 1), ByteArray(20), ByteArray(8))
        }
    }

    @Test
    fun hkdfExtractAndExpand_emptyIkm() {
        shouldThrow<ByteArrayLengthException> {
            hkdfExtractAndExpand(ByteArray(HKDF_SALT_LEN), ByteArray(0), ByteArray(8))
        }
    }

    @Test
    fun hkdfExtractAndExpand_emptyInfo() {
        shouldThrow<ByteArrayLengthException> {
            hkdfExtractAndExpand(ByteArray(HKDF_SALT_LEN), ByteArray(20), ByteArray(0))
        }
    }

    @Test
    fun hkdfExtractAndExpand_outputsExpectedLength() {
        hkdfExtractAndExpand(
            ByteArray(HKDF_SALT_LEN),
            ByteArray(20),
            ByteArray(8),
        ).size shouldBe HKDF_LEN
    }
}
