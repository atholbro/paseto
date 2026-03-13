package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi
import net.aholbrook.paseto.protocol.Version
import java.io.IOException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException

/**
 * Base exception for key parsing/validation/usage failures.
 *
 * @param message Human-readable message.
 * @param cause Optional source exception.
 */
open class KeyException @InternalApi constructor(message: String, cause: Throwable? = null) :
    PasetoException(message, cause)

/**
 * Thrown when a key has an invalid byte length for the target protocol.
 *
 * @property actual Provided key length.
 * @property allowed Allowed lengths.
 */
class KeyLengthException @InternalApi constructor(val actual: Int, val allowed: Array<Int>) :
    KeyException("Key length $actual is not in the list of allowed key lengths: $allowed.")

/**
 * Thrown when a key is used for the wrong purpose (`local` vs `public`).
 *
 * @property expected Required purpose.
 * @property actual Key purpose provided.
 */
class KeyPurposeException @InternalApi constructor(val expected: String, val actual: String) :
    KeyException("Got wrong Key purpose: $actual given, expected: $expected.")

/**
 * Thrown when a key version does not match requested token version.
 *
 * @property expected Required version.
 * @property actual Key version provided.
 */
class KeyVersionException @InternalApi constructor(val expected: Version, val actual: Version) :
    KeyException("Got wrong Key version: $actual given, expected: $expected.")

/**
 * Thrown when attempting to reuse key material after it has been cleared.
 */
class KeyClearedException @InternalApi constructor() :
    KeyException("Key instance has already been consumed and cleared. Load a new key for each operation.")

/**
 * Thrown when PEM input has an unsupported block type.
 *
 * @property type PEM block type encountered.
 */
class KeyPemUnsupportedTypeException @InternalApi constructor(val type: String) :
    KeyException("Unsupported PEM type: $type")

/**
 * Base exception for EC key conversion/validation failures.
 *
 * @param msg Human-readable message.
 * @param cause Optional source exception.
 */
class EcKeyException @InternalApi constructor(msg: String, cause: Throwable? = null) : KeyException(msg, cause)

/**
 * Thrown when loading key material from a PKCS#12 keystore fails.
 *
 * @property reason High-level reason category.
 * @param cause Optional source exception.
 */
class Pkcs12LoadException @InternalApi constructor(val reason: Reason, cause: Throwable? = null) :
    KeyException(
        when (reason) {
            Reason.ALGORITHM_NOT_FOUND -> "Key algorithm not found - $cause"
            Reason.UNRECOVERABLE_KEY -> "Unrecoverable key - $cause"
            Reason.IO_EXCEPTION -> "IO exception - $cause"
            Reason.INCORRECT_PASSWORD -> "Given keystore and/or key password was incorrect."
            Reason.CERTIFICATE_ERROR -> "Certificate error - $cause"
            Reason.PRIVATE_KEY_NOT_FOUND -> "Unable to locate private key in keystore."
            Reason.PUBLIC_KEY_NOT_FOUND -> "Unable to locate public key / certificate in keystore."
        },
        cause,
    ) {

    /** @param e Wrapped [NoSuchAlgorithmException]. */
    @InternalApi constructor(e: NoSuchAlgorithmException) : this(Reason.ALGORITHM_NOT_FOUND, e)

    /** @param e Wrapped [UnrecoverableKeyException]. */
    @InternalApi constructor(e: UnrecoverableKeyException) : this(Reason.UNRECOVERABLE_KEY, e)

    /** @param e Wrapped [CertificateException]. */
    @InternalApi constructor(e: CertificateException) : this(Reason.CERTIFICATE_ERROR, e)

    /**
     * @param e Wrapped [IOException].
     */
    @InternalApi constructor(e: IOException) : this(
        reason = if (e.cause != null && e.cause is UnrecoverableKeyException) {
            Reason.INCORRECT_PASSWORD
        } else {
            Reason.IO_EXCEPTION
        },
        cause = e,
    )

    /** Categorical failure reason when loading a PKCS#12 keystore. */
    enum class Reason {
        /** Required crypto algorithm is unavailable. */
        ALGORITHM_NOT_FOUND,

        /** Key could not be recovered from keystore. */
        UNRECOVERABLE_KEY,

        /** General IO failure while reading the keystore. */
        IO_EXCEPTION,

        /** Supplied keystore or key password was incorrect. */
        INCORRECT_PASSWORD,

        /** Certificate parsing/validation failure. */
        CERTIFICATE_ERROR,

        /** Private key entry was not found. */
        PRIVATE_KEY_NOT_FOUND,

        /** Public key/certificate entry was not found. */
        PUBLIC_KEY_NOT_FOUND,
    }
}
