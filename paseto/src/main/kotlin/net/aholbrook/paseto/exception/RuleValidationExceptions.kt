package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi
import net.aholbrook.paseto.Token
import net.aholbrook.paseto.rules.Rule
import java.time.Instant

/**
 * Base exception for rule-engine validation failures.
 *
 * @param msg Human-readable message.
 * @property claim Claim name associated with failure.
 * @property token Token that failed validation.
 */
open class RuleValidationException(msg: String, val claim: String, val token: Token) : PasetoException(msg) {
    /** Rule instance that produced this error, when available. */
    var rule: Rule? = null
        internal set
}

/** Thrown when `iat >= exp` while encoding. */
class TokenExpiresBeforeIssuedException(token: Token) :
    RuleValidationException(
        "token would expire (${token.expiresAt}) before it was issued (${token.issuedAt})",
        "iat",
        token,
    )

/** Thrown when `nbf >= exp` while encoding. */
class TokenIsNotValidUntilAfterExpiration(token: Token) :
    RuleValidationException(
        "token is not valid (${token.notBefore}) until after it expires (${token.expiresAt})",
        "exp",
        token,
    )

/**
 * Thrown when a required claim is missing.
 *
 * @param claim Name of the missing claim.
 * @param token Token being validated.
 */
class MissingClaimException(claim: String, token: Token) :
    RuleValidationException("Token is missing required claim $claim.", claim, token)

/**
 * Thrown when the token is expired at decode time.
 *
 * @param time Expiration instant.
 * @param token Token being validated.
 */
class ExpiredTokenException(time: Instant, token: Token) :
    RuleValidationException("Token expired at $time.", "exp", token)

/**
 * Thrown when `aud` does not match expected audience.
 *
 * @property expected Required audience value.
 * @property audience Audience value found in token.
 * @param token Token being validated.
 */
class IncorrectAudienceException(val expected: String, val audience: String?, token: Token) :
    RuleValidationException("Token audience is \"$audience\", required: \"$expected\"", "aud", token)

/**
 * Thrown when `jti` does not match expected token id.
 *
 * @property expected Required token id value.
 * @property tokenId Token id value found in token.
 * @param token Token being validated.
 */
class IncorrectTokenIdException(val expected: String, val tokenId: String?, token: Token) :
    RuleValidationException("Token ID is \"$tokenId\", required: \"$expected\"", "jti", token)

/**
 * Thrown when `iss` does not match expected issuer.
 *
 * @property expected Required issuer.
 * @property issuer Issuer found in token.
 * @param token Token being validated.
 */
class IncorrectIssuerException(val expected: String, val issuer: String?, token: Token) :
    RuleValidationException("Token issued by \"$issuer\", required: \"$expected\"", "iss", token)

/**
 * Thrown when `sub` does not match expected subject.
 *
 * @property expected Required subject.
 * @property subject Subject found in token.
 * @param token Token being validated.
 */
class IncorrectSubjectException(val expected: String, val subject: String, token: Token) :
    RuleValidationException("Token subject is \"$subject\", required: \"$expected\"", "sub", token)

/**
 * Thrown when token issue time is in the future.
 *
 * @param now Current instant at validation time.
 * @param issuedAt Token issue time.
 * @param token Token being validated.
 */
class IssuedInFutureException(now: Instant, issuedAt: Instant?, token: Token) :
    RuleValidationException("Token was issued at a future date/time $issuedAt, currently: $now", "iat", token)

/**
 * Thrown when token is used before its `nbf` instant.
 *
 * @param time `nbf` time from token.
 * @param token Token being validated.
 */
class NotYetValidException(time: Instant, token: Token) :
    RuleValidationException("Token is not valid until $time.", "nbf", token)

/**
 * Aggregates multiple rule failures from a single encode/decode operation.
 *
 * @property token Token that failed validation.
 */
class MultipleValidationErrorsException @InternalApi constructor(val token: Token) :
    PasetoException("Multiple verification errors.") {

    private val internalExceptions = mutableListOf<RuleValidationException>()

    /** All collected validation exceptions. */
    val exceptions: List<RuleValidationException> get() = internalExceptions

    internal fun add(e: RuleValidationException) {
        internalExceptions.add(e)
    }

    override val message: String get() =
        "Multiple verification errors:\n${exceptions.joinToString("\n") { "  $it" }}"
}
