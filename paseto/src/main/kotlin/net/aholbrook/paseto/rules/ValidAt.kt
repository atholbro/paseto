package net.aholbrook.paseto.rules

import net.aholbrook.paseto.Token
import net.aholbrook.paseto.exception.ExpiredTokenException
import net.aholbrook.paseto.exception.IssuedInFutureException
import net.aholbrook.paseto.exception.MissingClaimException
import net.aholbrook.paseto.exception.NotYetValidTokenException
import net.aholbrook.paseto.exception.TokenExpiresBeforeIssuedException
import net.aholbrook.paseto.exception.TokenIsNotValidUntilAfterExpiration
import net.aholbrook.paseto.rules.Rule.Mode
import java.time.Clock

/**
 * Verifies that the token is not expired or validated before it's "Not Before" time.
 *
 * @param clock To allow overriding clock source for unit tests.
 */
@ConsistentCopyVisibility
data class ValidAt internal constructor(private val clock: Clock) : Rule {
    constructor() : this(Clock.systemUTC())

    override operator fun invoke(token: Token, mode: Mode, currentResults: Map<Rule, RuleResult>) {
        if (token.issuedAt == null) {
            throw MissingClaimException("iat", token)
        }
        if (token.notBefore == null) {
            throw MissingClaimException("nbf", token)
        }
        if (token.expiresAt == null) {
            throw MissingClaimException("exp", token)
        }

        if (mode == Mode.ENCODE) {
            // verify the token was not issued after it expired (iat <= exp)
            if (token.issuedAt.isAfter(token.expiresAt)) {
                throw TokenExpiresBeforeIssuedException(token)
            }

            // nbf < exp
            if (!token.expiresAt.isAfter(token.notBefore)) {
                throw TokenIsNotValidUntilAfterExpiration(token)
            }
        }

        if (mode == Mode.DECODE) {
            val now = clock.instant()

            // now <= exp
            if (now.isAfter(token.expiresAt)) {
                throw ExpiredTokenException(token.expiresAt, this, token)
            }

            // now >= iat
            if (now.isBefore(token.issuedAt)) {
                throw IssuedInFutureException(now, token.issuedAt, this, token)
            }

            // now >= nbf
            if (now.isBefore(token.notBefore)) {
                throw NotYetValidTokenException(token.notBefore, this, token)
            }
        }
    }
}
