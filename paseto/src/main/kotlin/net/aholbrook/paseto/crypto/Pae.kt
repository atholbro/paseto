package net.aholbrook.paseto.crypto

private fun le64(value: Long): ByteArray {
    var n = value
    val result = ByteArray(8)
    for (i in 0..7) {
        if (i == 7) {
            n = n and 127L
        }

        result[i] = (n and 255L).toByte()
        n = n shr 8
    }

    return result
}

private fun paeLen(vararg pieces: ByteArray): Int = 8 + 8 * pieces.size + pieces.sumOf { it.size }

internal fun pae(vararg pieces: ByteArray): ByteArray {
    val result = ByteArray(paeLen(*pieces))
    var resultPos = 0

    System.arraycopy(le64(pieces.size.toLong()), 0, result, resultPos, 8)
    resultPos += 8
    for (i in pieces.indices) {
        System.arraycopy(le64(pieces[i].size.toLong()), 0, result, resultPos, 8)
        resultPos += 8
        System.arraycopy(pieces[i], 0, result, resultPos, pieces[i].size)
        resultPos += pieces[i].size
    }

    return result
}
