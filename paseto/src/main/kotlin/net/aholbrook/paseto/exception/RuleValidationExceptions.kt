package net.aholbrook.paseto.exception

import net.aholbrook.paseto.PasetoToken
import net.aholbrook.paseto.rules.Rule
import java.time.Instant

open class RuleValidationException(msg: String, val claim: String, val rule: Rule?, token: PasetoToken) :
    PasetoTokenException(msg, token)

class ExpiredTokenException(time: Instant, rule: Rule, token: PasetoToken) :
    RuleValidationException("Token expired at $time.", "exp", rule, token)

class IncorrectAudienceException(val expected: String, val audience: String?, rule: Rule, token: PasetoToken) :
    RuleValidationException("Token audience is \"$audience\", required: \"$expected\"", "aud", rule, token)

class IncorrectTokenIdException(val expected: String, val audience: String?, rule: Rule, token: PasetoToken) :
    RuleValidationException("Token ID is \"$audience\", required: \"$expected\"", "jti", rule, token)

class IncorrectIssuerException(val expected: String, val issuer: String?, rule: Rule, token: PasetoToken) :
    RuleValidationException("Token issued by \"$issuer\", required: \"$expected\"", "iss", rule, token)

class IncorrectSubjectException(val expected: String?, val subject: String, rule: Rule, token: PasetoToken) :
    RuleValidationException("Token subject is \"$subject\", required: \"$expected\"", "sub", rule, token)

class IssuedInFutureException(now: Instant, issuedAt: Instant?, rule: Rule, token: PasetoToken) :
    RuleValidationException("Token was issued at a future date/time $issuedAt, currently: $now", "iat", rule, token)

class NotYetValidTokenException(time: Instant, rule: Rule, token: PasetoToken) :
    RuleValidationException("Token is not valid until $time.", "nbf", rule, token)

class MultipleValidationExceptions(token: PasetoToken) :
    PasetoTokenException("Multiple verification errors.", token) {

    private val internalExceptions = mutableListOf<PasetoTokenException>()
    val exceptions: List<PasetoTokenException> get() = internalExceptions

    fun add(e: PasetoTokenException) {
        internalExceptions.add(e)
    }

    override val message: String get() =
        "Multiple verification errors:\n${exceptions.joinToString("\n") { "  $it" }}"
}
