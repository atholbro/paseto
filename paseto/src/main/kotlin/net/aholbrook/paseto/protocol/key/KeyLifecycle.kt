package net.aholbrook.paseto.protocol.key

/**
 * Defines whether key material should be retained or cleared after use.
 */
enum class KeyLifecycle {
    /** Keep key material available for reuse across operations. */
    PERSISTENT,

    /** Clear key material after operation (encode/decode). */
    EPHEMERAL,
}
