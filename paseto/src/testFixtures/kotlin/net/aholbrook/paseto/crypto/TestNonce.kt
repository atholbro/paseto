package net.aholbrook.paseto.crypto

import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic

fun <T> withTestNonce(nonce: ByteArray?, block:() -> T): T {
    if (nonce == null) { return block() }

    try {
        mockkStatic("net.aholbrook.paseto.crypto.RngKt")
        every { generateNonce(any()) } returns nonce
        return block()
    } finally {
        unmockkStatic("net.aholbrook.paseto.crypto.RngKt")
    }
}
