package net.aholbrook.paseto.rules

import net.aholbrook.paseto.PasetoToken
import net.aholbrook.paseto.exception.ExpiredTokenException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.exception.TokenExpiresBeforeIssuedException
import net.aholbrook.paseto.rules.Rule.Mode
import java.time.Clock

/**
 * Verifies that the token is not expired.
 *
 * @param clock To allow overriding clock source for unit tests.
 */
@ConsistentCopyVisibility
data class NotExpired internal constructor(
    private val clock: Clock,
) : Rule {
    constructor() : this(Clock.systemUTC())

    override operator fun invoke(token: PasetoToken, mode: Mode, currentResults: Map<Rule, RuleResult>) {
        if (token.expiresAt == null) {
            throw MissingClaimException("exp", token)
        }

        if (mode == Mode.ENCODE) {
            if (token.issuedAt != null && !token.issuedAt.isBefore(token.expiresAt)) {
                throw TokenExpiresBeforeIssuedException(token)
            }
        }

        if (mode == Mode.DECODE) {
            if (clock.instant().isAfter(token.expiresAt)) {
                throw ExpiredTokenException(token.expiresAt, this, token)
            }
        }
    }
}
