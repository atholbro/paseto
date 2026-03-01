package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.exception.ByteArrayLengthException
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

internal const val HKDF_SALT_LEN = 16
internal const val HKDF_LEN = 32

internal fun hkdfExtractAndExpand(salt: ByteArray, inputKeyingMaterial: ByteArray, info: ByteArray): ByteArray {
    if (salt.size != HKDF_SALT_LEN) {
        throw ByteArrayLengthException("salt", salt.size, HKDF_SALT_LEN, true)
    }

    return hkdfSha384(HKDF_LEN, inputKeyingMaterial, info, salt)
}

internal fun hkdfSha384(length: Int, inputKeyingMaterial: ByteArray, info: ByteArray, salt: ByteArray?): ByteArray {
    if (inputKeyingMaterial.isEmpty()) {
        throw ByteArrayLengthException("inputKeyingMaterial", inputKeyingMaterial.size, 1, false)
    }
    if (info.isEmpty()) {
        throw ByteArrayLengthException("info", info.size, 1, false)
    }

    val hkdf = HKDFBytesGenerator(SHA384Digest())
    hkdf.init(HKDFParameters(inputKeyingMaterial, salt, info))
    return ByteArray(length).also { hkdf.generateBytes(it, 0, it.size) }
}
