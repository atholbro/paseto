package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi
import net.aholbrook.paseto.PasetoToken
import net.aholbrook.paseto.protocol.Version

open class CryptoProviderException @InternalApi constructor(s: String?, throwable: Throwable?) :
    RuntimeException(s, throwable)

open class PasetoException @InternalApi constructor(msg: String, cause: Throwable? = null) :
    RuntimeException(msg, cause)

class ImplicitAssertionsNotSupportedException @InternalApi constructor(actual: Version) :
    PasetoException("Implicit assertions are not supported for " + actual.name + " tokens.")

class CannotSignWithoutSecretKey @InternalApi constructor() :
    PasetoException("Token services without a secret key do not support signing.")

open class PasetoStringException @InternalApi constructor(s: String, val token: String, cause: Throwable? = null) :
    PasetoException(s, cause)

open class PasetoPayloadException @InternalApi constructor(
    s: String,
    val payload: ByteArray,
    cause: Throwable? = null,
) : PasetoException(s, cause)

class EncryptionException @InternalApi constructor() : PasetoException("Failed to encrypt payload.")

class DecryptionException @InternalApi constructor(token: String) :
    PasetoStringException("Failed to decrypt token.", token)

open class InvalidFooterException @InternalApi constructor(msg: String, cause: Throwable? = null) :
    PasetoException(msg, cause)

class GenericInvalidFooterException @InternalApi constructor(val given: String?, val expected: String) :
    PasetoException("Invalid footer in token: \"$given\" expected: \"$expected\".")

class FooterExceedsMaxLengthException @InternalApi constructor(val length: Int, val max: Int) :
    InvalidFooterException("Footer of length $length exceeds maximum length $max.")

class FooterExceedsMaxDepthException @InternalApi constructor(val depth: Int, val max: Int) :
    InvalidFooterException("Json footer with depth $depth exceeds maximum nesting depth $max.")

class FooterExceedsMaxKeysException @InternalApi constructor(val keys: Int, val max: Int) :
    InvalidFooterException("Json footer with keys $keys exceeds maximum keys $max.")

class FooterJsonParseException @InternalApi constructor(message: String?, cause: Throwable) :
    InvalidFooterException(message ?: "", cause)

class InvalidHeaderException @InternalApi constructor(val given: String?, val expected: String, token: String) :
    PasetoStringException("Invalid header in token: \"$given\", expected: \"$expected\".", token)

class SigningException @InternalApi constructor(payload: ByteArray) :
    PasetoPayloadException("Failed to sign payload.", payload)

class SignatureVerificationException @InternalApi constructor(token: String) :
    PasetoStringException("Failed to verify token signature.", token)

open class PasetoTokenException @InternalApi constructor(s: String, val token: PasetoToken) : PasetoException(s)

class TokenExpiresBeforeIssuedException @InternalApi constructor(token: PasetoToken) :
    PasetoTokenException("token would expire (${token.expiresAt}) before it was issued (${token.issuedAt})", token)

class TokenIsNotValidUntilAfterExpiration @InternalApi constructor(token: PasetoToken) :
    PasetoTokenException("token is not valid (${token.notBefore}) until after it expires (${token.expiresAt})", token)

class MissingClaimException @InternalApi constructor(val claim: String, token: PasetoToken) :
    PasetoTokenException("Token is missing required claim $claim.", token)

class PasetoParseException @InternalApi constructor(val reason: Reason, token: String) :
    PasetoStringException(
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
