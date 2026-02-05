package net.aholbrook.paseto.crypto

import java.security.SecureRandom

internal val rng = SecureRandom()

internal fun randomBytes(size: Int): ByteArray = ByteArray(size).also { rng.nextBytes(it) }

internal fun generateNonce(size: Int): ByteArray = randomBytes(size)
