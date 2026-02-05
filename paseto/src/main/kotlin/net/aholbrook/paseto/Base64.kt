package net.aholbrook.paseto

import kotlin.io.encoding.Base64

internal val Base64.Default.UrlSafeNoPadding: Base64 by lazy {
    Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
}

internal fun Base64.decodeOrNull(
    source: CharSequence,
    startIndex: Int = 0,
    endIndex: Int = source.length,
): ByteArray? = try {
    decode(source, startIndex, endIndex)
} catch (_: IllegalArgumentException) {
    null
}
