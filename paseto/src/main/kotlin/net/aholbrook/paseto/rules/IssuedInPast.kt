package net.aholbrook.paseto.rules

import net.aholbrook.paseto.Token
import net.aholbrook.paseto.exception.IssuedInFutureException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.rules.Rule.Mode
import java.time.Clock

/**
 * Ensures that the token was issued in the past (or current instant).
 *
 * @note Instants are truncated to seconds precision.
 * @param clock To allow overriding clock source for unit tests.
 */
@ConsistentCopyVisibility
data class IssuedInPast internal constructor(private val clock: Clock) : Rule {
    constructor() : this(Clock.systemUTC())

    override operator fun invoke(token: Token, mode: Rule.Mode, currentResults: Map<Rule, RuleResult>) {
        if (token.issuedAt == null) {
            throw MissingClaimException("iat", token)
        }

        if (mode == Mode.DECODE) {
            val now = clock.instant()

            if (now.isBefore(token.issuedAt)) {
                throw IssuedInFutureException(now, token.issuedAt, this, token)
            }
        }
    }
}
