package net.aholbrook.paseto.rules

import net.aholbrook.paseto.Token
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.exception.IncorrectTokenIdException
import net.aholbrook.paseto.exception.MissingClaimException

/**
 * Verifies that the token id (jti) claim matches the given value.
 *
 * @param tokenId The expected tokenId for the token.
 */
data class IdentifiedBy(val tokenId: String) : Rule {
    override operator fun invoke(token: Token, mode: Rule.Mode, currentResults: Map<Rule, RuleResult>) {
        if (token.tokenId.isNullOrEmpty()) {
            throw MissingClaimException("jti", token)
        }

        if (!token.tokenId.constantTimeEquals(tokenId)) {
            throw IncorrectTokenIdException(tokenId, token.tokenId, token)
        }
    }
}
