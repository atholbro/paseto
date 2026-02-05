package net.aholbrook.paseto.exception

import java.io.FileNotFoundException
import java.io.IOException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException

class Pkcs12LoadException(val reason: Reason, cause: Throwable? = null) :
    PasetoException(
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

    constructor(e: FileNotFoundException) : this(Reason.FILE_NOT_FOUND, e)
    constructor(e: NoSuchAlgorithmException) : this(Reason.ALGORITHM_NOT_FOUND, e)
    constructor(e: UnrecoverableKeyException) : this(Reason.UNRECOVERABLE_KEY, e)
    constructor(e: CertificateException) : this(Reason.CERTIFICATE_ERROR, e)

    constructor(e: IOException) : this(
        reason = if (e.cause != null && e.cause is UnrecoverableKeyException) {
            Reason.INCORRECT_PASSWORD
        } else {
            Reason.IO_EXCEPTION
        },
        cause = e
    )

    enum class Reason {
        FILE_NOT_FOUND,
        ALGORITHM_NOT_FOUND,
        UNRECOVERABLE_KEY,
        IO_EXCEPTION,
        INCORRECT_PASSWORD,
        CERTIFICATE_ERROR,
        PRIVATE_KEY_NOT_FOUND,
        PUBLIC_KEY_NOT_FOUND
    }
}
