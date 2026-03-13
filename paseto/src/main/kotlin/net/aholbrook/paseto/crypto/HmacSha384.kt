package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.exception.ByteArrayLengthException
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter

internal fun hmacSha384(m: ByteArray, key: ByteArray): ByteArray {
    if (m.isEmpty()) {
        throw ByteArrayLengthException("m", m.size, 1, false)
    }
    if (key.isEmpty()) {
        throw ByteArrayLengthException("key", key.size, 1, false)
    }

    val hmac = HMac(SHA384Digest())
    hmac.init(KeyParameter(key))
    hmac.update(m, 0, m.size)
    return ByteArray(hmac.macSize).also { hmac.doFinal(it, 0) }
}
