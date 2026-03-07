package net.aholbrook.paseto.rules

import net.aholbrook.paseto.Token
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.exception.IncorrectIssuerException
import net.aholbrook.paseto.exception.MissingClaimException

/**
 * Verifies that the token Issuer (iss) claim matches the given value.
 *
 * @param issuer The expected issuer of the token.
 */
data class IssuedBy(val issuer: String) : Rule {
    override operator fun invoke(token: Token, mode: Rule.Mode, currentResults: Map<Rule, RuleResult>) {
        if (token.issuer.isNullOrEmpty()) {
            throw MissingClaimException("iss", token)
        }

        if (!token.issuer.constantTimeEquals(issuer)) {
            throw IncorrectIssuerException(issuer, token.issuer, this, token)
        }
    }
}
