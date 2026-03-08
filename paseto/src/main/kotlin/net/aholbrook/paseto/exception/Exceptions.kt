package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi
import net.aholbrook.paseto.protocol.Version

open class PasetoException @InternalApi constructor(msg: String, cause: Throwable? = null) :
    RuntimeException(msg, cause)

open class CryptoException @InternalApi constructor(s: String, throwable: Throwable?) :
    PasetoException(s, throwable)

class ImplicitAssertionsNotSupportedException @InternalApi constructor(actual: Version) :
    PasetoException("Implicit assertions are not supported for " + actual.name + " tokens.")

class CannotSignWithoutSecretKey @InternalApi constructor() :
    PasetoException("Token services without a secret key do not support signing.")

open class EncodedTokenException @InternalApi constructor(s: String, val token: String, cause: Throwable? = null) :
    PasetoException(s, cause)

class EncryptionException @InternalApi constructor() : PasetoException("Failed to encrypt payload.")

class DecryptionException @InternalApi constructor(token: String) :
    EncodedTokenException("Failed to decrypt token.", token)

open class InvalidFooterException @InternalApi constructor(msg: String, cause: Throwable? = null) :
    PasetoException(msg, cause)

class IncorrectFooterException @InternalApi constructor(val given: String?, val expected: String) :
    InvalidFooterException("Invalid footer in token: \"$given\" expected: \"$expected\".")

class FooterExceedsMaxLengthException @InternalApi constructor(val length: Int, val max: Int) :
    InvalidFooterException("Footer of length $length exceeds maximum length $max.")

class FooterExceedsMaxDepthException @InternalApi constructor(val depth: Int, val max: Int) :
    InvalidFooterException("Json footer with depth $depth exceeds maximum nesting depth $max.")

class FooterExceedsMaxKeysException @InternalApi constructor(val keys: Int, val max: Int) :
    InvalidFooterException("Json footer with keys $keys exceeds maximum keys $max.")

class FooterJsonParseException @InternalApi constructor(message: String?, cause: Throwable) :
    InvalidFooterException(message ?: "", cause)

class InvalidHeaderException @InternalApi constructor(val given: String?, val expected: String, token: String) :
    EncodedTokenException("Invalid header in token: \"$given\", expected: \"$expected\".", token)

class SigningException @InternalApi constructor(val payload: ByteArray) :
    PasetoException("Failed to sign payload.")

class SignatureVerificationException @InternalApi constructor(token: String) :
    EncodedTokenException("Failed to verify token signature.", token)

class TokenParseException @InternalApi constructor(val reason: Reason, token: String) :
    EncodedTokenException(
        when (reason) {
            Reason.MISSING_SECTIONS ->
                "Invalid token: \"$token\" unable to locate 3-4 paseto sections."

            Reason.PAYLOAD_LENGTH ->
                "Invalid token: \"$token\" payload section doesn't meet the minimum length requirements."

            Reason.INVALID_BASE64 ->
                "Invalid token: \"$token\" invalid base64 encoding."
        },
        token,
    ) {
    var minLength: Int = 0
        internal set

    enum class Reason {
        MISSING_SECTIONS,
        PAYLOAD_LENGTH,
        INVALID_BASE64,
    }
}
