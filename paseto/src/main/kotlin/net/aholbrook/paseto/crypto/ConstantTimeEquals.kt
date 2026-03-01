package net.aholbrook.paseto.crypto

import java.nio.charset.Charset

/**
 * Compare two byte arrays with constant-time semantics.
 *
 * If the two given byte arrays are of different length, then the receiving array is compared with itself before
 * returning false. Consequently, the receiver is required to be the user-supplied value in order to maintain
 * constant-time execution.
 *
 * See: http://codahale.com/a-lesson-in-timing-attacks
 *
 * @receiver Input from the user.
 * @param expected The expected byte array.
 * @return true if the arrays are equal, false if not.
 */
internal fun ByteArray.constantTimeEquals(expected: ByteArray): Boolean {
    if (size != expected.size) {
        var result = 0
        for (i in indices) {
            result = result or (this[i].toInt() xor this[i].toInt())
        }
        return false
    } else {
        var result = 0
        for (i in indices) {
            result = result or (this[i].toInt() xor expected[i].toInt())
        }
        return result == 0
    }
}

/**
 * Compare two strings with constant-time semantics.
 *
 * If the two given strings are of different length, then the given receiving is compared with itself before
 * returning false. Consequently, the receiver is required to be the user-supplied value in order to maintain
 * constant-time execution.
 *
 * See: http://codahale.com/a-lesson-in-timing-attacks
 *
 * @receiver Input from the user.
 * @param expected The expected byte array.
 * @return true if the arrays are equal, false if not.
 */
internal fun String.constantTimeEquals(expected: String, charset: Charset = Charsets.UTF_8): Boolean =
    toByteArray(charset).constantTimeEquals(expected.toByteArray(charset))
