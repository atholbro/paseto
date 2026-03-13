package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi
import net.aholbrook.paseto.protocol.Version

/**
 * Base exception type for public PASETO APIs.
 *
 * @param msg Human-readable error message.
 * @param cause Optional source exception.
 */
open class PasetoException @InternalApi constructor(msg: String, cause: Throwable? = null) :
    RuntimeException(msg, cause)

/**
 * Base exception for cryptographic operation failures.
 *
 * @param s Human-readable error message.
 * @param throwable Optional source exception.
 */
open class CryptoException @InternalApi constructor(s: String, throwable: Throwable?) :
    PasetoException(s, throwable)

/**
 * Thrown when implicit assertions are used with a protocol version that does not support them.
 *
 * @param actual Version used for the attempted operation.
 */
class ImplicitAssertionsNotSupportedException @InternalApi constructor(actual: Version) :
    PasetoException("Implicit assertions are not supported for " + actual.name + " tokens.")

/**
 * Thrown when attempting to sign with a [net.aholbrook.paseto.protocol.key.KeyPair]
 * that does not contain a secret key.
 */
class CannotSignWithoutSecretKey @InternalApi constructor() :
    PasetoException("Token services without a secret key do not support signing.")

/**
 * Base exception for failures involving an encoded token string.
 *
 * @param s Human-readable error message.
 * @property token Encoded token string that caused the error.
 * @param cause Optional source exception.
 */
open class EncodedTokenException @InternalApi constructor(s: String, val token: String, cause: Throwable? = null) :
    PasetoException(s, cause)

/** Thrown when local-token encryption fails. */
class EncryptionException @InternalApi constructor() : PasetoException("Failed to encrypt payload.")

/**
 * Thrown when local-token decryption fails.
 *
 * @param token Encoded token that failed decryption.
 */
class DecryptionException @InternalApi constructor(token: String) :
    EncodedTokenException("Failed to decrypt token.", token)

/**
 * Base exception for footer parsing/validation errors.
 *
 * @param msg Human-readable error message.
 * @param cause Optional source exception.
 */
open class InvalidFooterException @InternalApi constructor(msg: String, cause: Throwable? = null) :
    PasetoException(msg, cause)

/**
 * Thrown when token footer does not match an expected footer value.
 *
 * @property given Footer decoded from the token.
 * @property expected Footer required by caller.
 */
class IncorrectFooterException @InternalApi constructor(val given: String?, val expected: String) :
    InvalidFooterException("Invalid footer in token: \"$given\" expected: \"$expected\".")

/**
 * Thrown when footer text exceeds configured maximum length.
 *
 * @property length Actual footer length.
 * @property max Allowed maximum length.
 */
class FooterExceedsMaxLengthException @InternalApi constructor(val length: Int, val max: Int) :
    InvalidFooterException("Footer of length $length exceeds maximum length $max.")

/**
 * Thrown when JSON footer depth exceeds configured maximum depth.
 *
 * @property depth Actual JSON nesting depth.
 * @property max Allowed maximum depth.
 */
class FooterExceedsMaxDepthException @InternalApi constructor(val depth: Int, val max: Int) :
    InvalidFooterException("Json footer with depth $depth exceeds maximum nesting depth $max.")

/**
 * Thrown when JSON footer key count exceeds configured maximum.
 *
 * @property keys Actual number of keys.
 * @property max Allowed maximum number of keys.
 */
class FooterExceedsMaxKeysException @InternalApi constructor(val keys: Int, val max: Int) :
    InvalidFooterException("Json footer with keys $keys exceeds maximum keys $max.")

/**
 * Thrown when footer parsing in claims mode fails.
 *
 * @param message Parse error message.
 * @param cause Source parse exception.
 */
class FooterJsonParseException @InternalApi constructor(message: String?, cause: Throwable) :
    InvalidFooterException(message ?: "", cause)

/**
 * Thrown when an encoded token header is not the expected value.
 *
 * @property given Header found in token.
 * @property expected Header required by verifier.
 * @param token Encoded token that failed header validation.
 */
class InvalidHeaderException @InternalApi constructor(val given: String?, val expected: String, token: String) :
    EncodedTokenException("Invalid header in token: \"$given\", expected: \"$expected\".", token)

/**
 * Thrown when public-token signing fails.
 *
 * @property payload Payload bytes that could not be signed.
 */
class SigningException @InternalApi constructor(val payload: ByteArray) : PasetoException("Failed to sign payload.")

/**
 * Thrown when public-token signature verification fails.
 *
 * @param token Encoded token that failed verification.
 */
class SignatureVerificationException @InternalApi constructor(token: String) :
    EncodedTokenException("Failed to verify token signature.", token)

/**
 * Thrown when a token cannot be parsed into required sections/payload.
 *
 * @property reason Parse failure category.
 * @param token Encoded token that failed parsing.
 */
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
    /**
     * Required minimum payload length when [reason] is [Reason.PAYLOAD_LENGTH].
     */
    var minLength: Int = 0
        internal set

    /** Categorical parse failure reason. */
    enum class Reason {
        /** Token does not contain required dotted sections. */
        MISSING_SECTIONS,

        /** Decoded payload does not meet protocol minimum length requirements. */
        PAYLOAD_LENGTH,

        /** One or more token sections are not valid base64url text. */
        INVALID_BASE64,
    }
}
