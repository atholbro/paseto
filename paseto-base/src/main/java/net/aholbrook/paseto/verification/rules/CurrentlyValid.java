package net.aholbrook.paseto.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.exception.verification.rules.ExpiredTokenException;
import net.aholbrook.paseto.exception.verification.rules.MissingClaimException;
import net.aholbrook.paseto.verification.PasetoVerificationContext;

import java.time.Clock;
import java.time.OffsetDateTime;

public class CurrentlyValid implements Rule {
	public final static String NAME = "CURRENTLY_VALID";
	private final OffsetDateTime time;

	/**
	 * Verifies that the token is not expired or validated before it's "Not Before" time.
	 *
	 * This call sets the "check time" to Clock.systemUTC() and should be used in most cases.
	 */
	public CurrentlyValid() {
		time = OffsetDateTime.now(Clock.systemUTC());
	}

	/**
	 * Verifies that the token is not expired or validated before it's "Not Before" time.
	 *
	 * This constructor allows the caller to specify the instant ("NOW") at which to check for validity. It's intended
	 * for unit testing and edge cases. In most cases you should use the no argument constructor which uses the
	 * current UTC system time.
	 * @param time The time used for validity checks.
	 */
	public CurrentlyValid(OffsetDateTime time) {
		this.time = time;
	}

	@Override
	public String name() {
		return NAME;
	}

	@Override
	public void check(Token token, PasetoVerificationContext context) {
		// If no expiry time was set, then we treat the token as expired.
		if (token.getExpiration() == null) {
			throw new MissingClaimException(Token.CLAIM_EXPIRATION, NAME, token);
		}

		// Check "Not Before" if provided.
		if (token.getNotBefore() != null && token.getNotBefore().isAfter(time)) {
			throw new ExpiredTokenException(ExpiredTokenException.Reason.NOT_YET_VALID,
					token.getNotBefore(), NAME, token);
		}

		// Note: issued at times can be checked with the IssuedInPast rule.

		// Finally we check the expiration time.
		if (token.getExpiration().isBefore(time)) {
			throw new ExpiredTokenException(ExpiredTokenException.Reason.EXPIRED,
					token.getExpiration(), NAME, token);
		}
	}
}
