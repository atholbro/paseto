package net.aholbrook.paseto.crypto

import io.kotest.assertions.throwables.shouldThrow
import net.aholbrook.paseto.exception.ByteArrayRangeException
import org.junit.jupiter.api.Test

private val BLAKE2B_OUTPUT = ByteArray(BLAKE2B_BYTES_MIN)
private val BLAKE2B_INPUT = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
private val BLAKE2B_KEY = ByteArray(BLAKE2B_KEYBYTES_MIN)

class Blake2bTests {
    @Test
    fun blake2b_outShort() {
        shouldThrow<ByteArrayRangeException> {
            blake2b(ByteArray(BLAKE2B_BYTES_MIN - 1), BLAKE2B_KEY, BLAKE2B_INPUT)
        }
    }

    @Test
    fun blake2b_outLong() {
        shouldThrow<ByteArrayRangeException> {
            blake2b(ByteArray(BLAKE2B_BYTES_MAX + 1), BLAKE2B_KEY, BLAKE2B_INPUT)
        }
    }

    @Test
    fun blake2b_keyShort() {
        shouldThrow<ByteArrayRangeException> {
            blake2b(BLAKE2B_OUTPUT, ByteArray(BLAKE2B_KEYBYTES_MIN - 1), BLAKE2B_INPUT)
        }
    }

    @Test
    fun blake2b_keyLong() {
        shouldThrow<ByteArrayRangeException> {
            blake2b(BLAKE2B_OUTPUT, ByteArray(BLAKE2B_KEYBYTES_MAX + 1), BLAKE2B_INPUT)
        }
    }
}
