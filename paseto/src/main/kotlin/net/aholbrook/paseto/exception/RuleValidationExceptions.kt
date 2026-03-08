package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi
import net.aholbrook.paseto.Token
import net.aholbrook.paseto.rules.Rule
import java.time.Instant


open class RuleValidationException (
    msg: String,
    val claim: String,
    val token: Token,
) : PasetoException(msg) {
    var rule: Rule? = null
        internal set
}

class TokenExpiresBeforeIssuedException(token: Token) :
    RuleValidationException("token would expire (${token.expiresAt}) before it was issued (${token.issuedAt})", "iat", token)

class TokenIsNotValidUntilAfterExpiration(token: Token, ) :
    RuleValidationException("token is not valid (${token.notBefore}) until after it expires (${token.expiresAt})", "exp", token)

class MissingClaimException(claim: String, token: Token, ) :
    RuleValidationException("Token is missing required claim $claim.", claim, token)

class ExpiredTokenException(time: Instant, token: Token) :
    RuleValidationException("Token expired at $time.", "exp", token)

class IncorrectAudienceException(
    val expected: String,
    val audience: String?,
    token: Token,
) : RuleValidationException("Token audience is \"$audience\", required: \"$expected\"", "aud", token)

class IncorrectTokenIdException(
    val expected: String,
    val tokenId: String?,
    token: Token,
) : RuleValidationException("Token ID is \"$tokenId\", required: \"$expected\"", "jti", token)

class IncorrectIssuerException(
    val expected: String,
    val issuer: String?,
    token: Token,
) : RuleValidationException("Token issued by \"$issuer\", required: \"$expected\"", "iss", token)

class IncorrectSubjectException(
    val expected: String,
    val subject: String,
    token: Token,
) : RuleValidationException("Token subject is \"$subject\", required: \"$expected\"", "sub", token)

class IssuedInFutureException(now: Instant, issuedAt: Instant?, token: Token) :
    RuleValidationException("Token was issued at a future date/time $issuedAt, currently: $now", "iat", token)

class NotYetValidException(time: Instant, token: Token) :
    RuleValidationException("Token is not valid until $time.", "nbf", token)

class MultipleValidationErrorsException @InternalApi constructor(val token: Token) :
    PasetoException("Multiple verification errors.") {

    private val internalExceptions = mutableListOf<RuleValidationException>()
    val exceptions: List<RuleValidationException> get() = internalExceptions

    internal fun add(e: RuleValidationException) {
        internalExceptions.add(e)
    }

    override val message: String get() =
        "Multiple verification errors:\n${exceptions.joinToString("\n") { "  $it" }}"
}
