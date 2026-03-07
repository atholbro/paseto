package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi
import net.aholbrook.paseto.Token
import net.aholbrook.paseto.rules.Rule
import java.time.Instant

open class RuleValidationException @InternalApi constructor(
    msg: String,
    val claim: String,
    val rule: Rule?,
    token: Token,
) : PasetoTokenException(msg, token)

class ExpiredTokenException @InternalApi constructor(time: Instant, rule: Rule, token: Token) :
    RuleValidationException("Token expired at $time.", "exp", rule, token)

class IncorrectAudienceException @InternalApi constructor(
    val expected: String,
    val audience: String?,
    rule: Rule,
    token: Token,
) : RuleValidationException("Token audience is \"$audience\", required: \"$expected\"", "aud", rule, token)

class IncorrectTokenIdException @InternalApi constructor(
    val expected: String,
    val tokenId: String?,
    rule: Rule,
    token: Token,
) : RuleValidationException("Token ID is \"$tokenId\", required: \"$expected\"", "jti", rule, token)

class IncorrectIssuerException @InternalApi constructor(
    val expected: String,
    val issuer: String?,
    rule: Rule,
    token: Token,
) : RuleValidationException("Token issued by \"$issuer\", required: \"$expected\"", "iss", rule, token)

class IncorrectSubjectException @InternalApi constructor(
    val expected: String?,
    val subject: String,
    rule: Rule,
    token: Token,
) : RuleValidationException("Token subject is \"$subject\", required: \"$expected\"", "sub", rule, token)

class IssuedInFutureException @InternalApi constructor(now: Instant, issuedAt: Instant?, rule: Rule, token: Token) :
    RuleValidationException("Token was issued at a future date/time $issuedAt, currently: $now", "iat", rule, token)

class NotYetValidTokenException @InternalApi constructor(time: Instant, rule: Rule, token: Token) :
    RuleValidationException("Token is not valid until $time.", "nbf", rule, token)

class MultipleValidationExceptions @InternalApi constructor(token: Token) :
    PasetoTokenException("Multiple verification errors.", token) {

    private val internalExceptions = mutableListOf<PasetoTokenException>()
    val exceptions: List<PasetoTokenException> get() = internalExceptions

    fun add(e: PasetoTokenException) {
        internalExceptions.add(e)
    }

    override val message: String get() =
        "Multiple verification errors:\n${exceptions.joinToString("\n") { "  $it" }}"
}
