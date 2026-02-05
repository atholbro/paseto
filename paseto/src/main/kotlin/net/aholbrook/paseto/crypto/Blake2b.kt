package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.exception.ByteArrayRangeException
import org.bouncycastle.crypto.digests.Blake2bDigest

internal const val BLAKE2B_BYTES_MIN = 16
internal const val BLAKE2B_BYTES_MAX = 64
internal const val BLAKE2B_KEYBYTES_MIN = 16
internal const val BLAKE2B_KEYBYTES_MAX = 64

internal fun blake2b(out: ByteArray, key: ByteArray, vararg input: ByteArray) {
    // check lengths
    if (out.size !in BLAKE2B_BYTES_MIN..BLAKE2B_BYTES_MAX) {
        throw ByteArrayRangeException("out", out.size, BLAKE2B_BYTES_MIN, BLAKE2B_BYTES_MAX)
    }
    if (key.size !in BLAKE2B_KEYBYTES_MIN..BLAKE2B_KEYBYTES_MAX) {
        throw ByteArrayRangeException("key", key.size, BLAKE2B_KEYBYTES_MIN, BLAKE2B_KEYBYTES_MAX)
    }

    val digest = Blake2bDigest(key, out.size, null, null)
    input.forEach { digest.update(it, 0, it.size) }
    digest.doFinal(out, 0)
}
