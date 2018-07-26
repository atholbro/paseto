package net.aholbrook.paseto.claims;

import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.exception.claims.ExpiredTokenException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.exception.claims.NotYetValidTokenException;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;

public class CurrentlyValid implements Claim {
	public final static String NAME = "CURRENTLY_VALID";
	public final static Duration DEFAULT_ALLOWABLE_DRIFT = Duration.ofSeconds(1);

	private final OffsetDateTime time;
	private final Duration allowableDrift;

	/**
	 * Verifies that the token is not expired or validated before it's "Not Before" time.
	 *
	 * This call sets the "check time" to Clock.systemUTC() and should be used in most cases.
	 *
	 * This constructor sets the allowable clock drift as DEFAULT_ALLOWABLE_DRIFT which is defined as 1 second. This
	 * relaxes the check by adding a 1 second window into the future during which the not before check will pass.
	 */
	public CurrentlyValid() {
		this(DEFAULT_ALLOWABLE_DRIFT);
	}

	/**
	 * Verifies that the token is not expired or validated before it's "Not Before" time.
	 *
	 * This call sets the "check time" to Clock.systemUTC() and should be used in most cases.
	 *
	 * @param allowableDrift Time window during which a token is considered valid even if it's not before time is in
	 *                       the future. Should be set to a small time window (default is 1 second) which allows for a
	 *                       slight clock drift between servers. Only applies to "not before" and not the expiration
	 *                       time.
	 */
	public CurrentlyValid(Duration allowableDrift) {
		this(null, allowableDrift);
	}

	/**
	 * Verifies that the token is not expired or validated before it's "Not Before" time.
	 *
	 * This constructor allows the caller to specify the instant ("NOW") at which to check for validity. It's intended
	 * for unit testing and edge cases. In most cases you should use the no argument constructor which uses the
	 * current UTC system time.
	 *
	 * @param time The time used for validity checks.
	 * @param allowableDrift Time window during which a token is considered valid even if it's not before time is in
	 *                       the future. Should be set to a small time window (default is 1 second) which allows for a
	 *                       slight clock drift between servers. Only applies to "not before" and not the expiration
	 *                       time.
	 */
	public CurrentlyValid(OffsetDateTime time, Duration allowableDrift) {
		this.time = time;
		this.allowableDrift = allowableDrift;
	}

	@Override
	public String name() {
		return NAME;
	}

	@Override
	public void check(Token token, VerificationContext context) {
		OffsetDateTime time = this.time == null ? OffsetDateTime.now(Clock.systemUTC()) : this.time;

		// If no expiry time was set, then we treat the token as expired.
		if (token.getExpiration() == null) {
			throw new MissingClaimException(Token.CLAIM_EXPIRATION, NAME, token);
		}

		// Check "Not Before" if provided.
		if (token.getNotBefore() != null) {
			if (token.getNotBefore().minus(allowableDrift).isAfter(time)) {
				throw new NotYetValidTokenException(token.getNotBefore(), NAME, token);
			}
		}

		// Note: issued at times can be checked with the IssuedInPast rule.

		// Finally we check the expiration time.
		if (token.getExpiration().isBefore(time)) {
			throw new ExpiredTokenException(token.getExpiration(), NAME, token);
		}
	}
}
