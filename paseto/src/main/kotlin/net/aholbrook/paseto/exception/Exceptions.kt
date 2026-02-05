package net.aholbrook.paseto.exception

import net.aholbrook.paseto.PasetoToken
import net.aholbrook.paseto.protocol.Version

open class CryptoProviderException(s: String?, throwable: Throwable?) : RuntimeException(s, throwable)

open class PasetoException(msg: String, cause: Throwable? = null) : RuntimeException(msg, cause)

class ImplicitAssertionsNotSupportedException(actual: Version) :
    PasetoException("Implicit assertions are not supported for " + actual.name + " tokens.")

class CannotSignWithoutSecretKey :
    PasetoException("Token services without a secret key do not support signing.")

open class PasetoStringException(s: String, val token: String) : PasetoException(s)

class EncryptionException : PasetoException("Failed to encrypt payload.")

class DecryptionException(token: String) : PasetoStringException("Failed to decrypt token.", token)

class InvalidFooterException(val given: String?, val expected: String, token: String) :
    PasetoStringException("Invalid footer in token: \"$given\" expected: \"$expected\".", token)

class InvalidHeaderException(val given: String?, val expected: String, token: String) :
    PasetoStringException("Invalid header in token: \"$given\", expected: \"$expected\".", token)

class SigningException(payload: String) : PasetoStringException("Failed to sign payload.", payload)

class SignatureVerificationException(token: String) : PasetoStringException("Failed to verify token signature.", token)

open class PasetoTokenException(s: String, val token: PasetoToken) : PasetoException(s)

class TokenExpiresBeforeIssuedException(token: PasetoToken) :
    PasetoTokenException("token would expire (${token.expiresAt}) before it was issued (${token.issuedAt})", token)

class TokenIsNotValidUntilAfterExpiration(token: PasetoToken) :
    PasetoTokenException("token is not valid (${token.notBefore}) until after it expires (${token.expiresAt})", token)

class MissingClaimException(val claim: String, token: PasetoToken) :
    PasetoTokenException("Token is missing required claim $claim.", token)

class PasetoParseException(val reason: Reason, token: String) :
    PasetoStringException(
        when (reason) {
            Reason.MISSING_SECTIONS ->
                "Invalid token: \"$token\" unable to locate 3-4 paseto sections."
            Reason.PAYLOAD_LENGTH ->
                "Invalid token: \"$token\" payload section doesn't meet the minimum length requirements."
            Reason.INVALID_BASE64 ->
                "Invalid token: \"$token\" invalid base64 encoding."
        },
        token
    ) {
    var minLength: Int = 0
        internal set

    enum class Reason {
        MISSING_SECTIONS,
        PAYLOAD_LENGTH,
        INVALID_BASE64,
    }
}
