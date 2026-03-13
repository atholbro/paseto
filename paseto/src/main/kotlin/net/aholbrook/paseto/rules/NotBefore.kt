package net.aholbrook.paseto.rules

import net.aholbrook.paseto.Token
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.exception.NotYetValidException
import net.aholbrook.paseto.exception.TokenIsNotValidUntilAfterExpiration
import net.aholbrook.paseto.rules.Rule.Mode
import java.time.Clock

/**
 * Verifies the token's notBefore time.
 *
 * @param clock To allow overriding clock source for unit tests.
 */
@ConsistentCopyVisibility
data class NotBefore internal constructor(private val clock: Clock) : Rule {
    constructor() : this(Clock.systemUTC())

    override operator fun invoke(token: Token, mode: Mode, currentResults: Map<Rule, RuleResult>) {
        if (token.notBefore == null) {
            throw MissingClaimException("nbf", token)
        }

        if (mode == Mode.ENCODE) {
            if (token.expiresAt != null && !token.notBefore.isBefore(token.expiresAt)) {
                throw TokenIsNotValidUntilAfterExpiration(token)
            }
        }

        if (mode == Mode.DECODE) {
            if (clock.instant().isBefore(token.notBefore)) {
                throw NotYetValidException(token.notBefore, token)
            }
        }
    }
}
