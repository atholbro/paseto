package net.aholbrook.paseto.rules

import net.aholbrook.paseto.PasetoToken
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.exception.IncorrectAudienceException
import net.aholbrook.paseto.exception.MissingClaimException

/**
 * Verifies that the token Audience (aud) claim matches the given value.
 *
 * @param audience The expected audience for the token.
 */
data class ForAudience(val audience: String) : Rule {
    override operator fun invoke(token: PasetoToken, mode: Rule.Mode, currentResults: Map<Rule, RuleResult>) {
        if (token.audience.isNullOrEmpty()) {
            throw MissingClaimException("aud", token)
        }

        if (!token.audience.constantTimeEquals(audience)) {
            throw IncorrectAudienceException(audience, token.audience, this, token)
        }
    }
}
