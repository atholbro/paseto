package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi
import net.aholbrook.paseto.protocol.Version
import java.io.FileNotFoundException
import java.io.IOException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException

open class KeyException @InternalApi constructor(message: String, cause: Throwable? = null) :
    PasetoException(message, cause)

class KeyLengthException @InternalApi constructor(val actual: Int, val allowed: Array<Int>) :
    KeyException("Key length $actual is not in the list of allowed key lengths: $allowed.")

class KeyPurposeException @InternalApi constructor(val expected: String, val actual: String) :
    KeyException("Got wrong Key purpose: $actual given, expected: $expected.")

class KeyVersionException @InternalApi constructor(val expected: Version, val actual: Version) :
    KeyException("Got wrong Key version: $actual given, expected: $expected.")

class KeyClearedException @InternalApi constructor() :
    KeyException("Key instance has already been consumed and cleared. Load a new key for each operation.")

class KeyPemUnsupportedTypeException @InternalApi constructor(val type: String) :
    KeyException("Unsupported PEM type: $type")

class EcKeyException @InternalApi constructor(msg: String, cause: Throwable? = null) : KeyException(msg, cause)

class Pkcs12LoadException @InternalApi constructor(val reason: Reason, cause: Throwable? = null) :
    KeyException(
        when (reason) {
            Reason.FILE_NOT_FOUND -> "File not found."
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

    @InternalApi constructor(e: FileNotFoundException) : this(Reason.FILE_NOT_FOUND, e)

    @InternalApi constructor(e: NoSuchAlgorithmException) : this(Reason.ALGORITHM_NOT_FOUND, e)

    @InternalApi constructor(e: UnrecoverableKeyException) : this(Reason.UNRECOVERABLE_KEY, e)

    @InternalApi constructor(e: CertificateException) : this(Reason.CERTIFICATE_ERROR, e)

    @InternalApi constructor(e: IOException) : this(
        reason = if (e.cause != null && e.cause is UnrecoverableKeyException) {
            Reason.INCORRECT_PASSWORD
        } else {
            Reason.IO_EXCEPTION
        },
        cause = e,
    )

    enum class Reason {
        FILE_NOT_FOUND,
        ALGORITHM_NOT_FOUND,
        UNRECOVERABLE_KEY,
        IO_EXCEPTION,
        INCORRECT_PASSWORD,
        CERTIFICATE_ERROR,
        PRIVATE_KEY_NOT_FOUND,
        PUBLIC_KEY_NOT_FOUND,
    }
}
