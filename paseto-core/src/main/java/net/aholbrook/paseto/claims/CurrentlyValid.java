package net.aholbrook.paseto.claims;

import net.aholbrook.paseto.exception.claims.ExpiredTokenException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.exception.claims.NotYetValidTokenException;
import net.aholbrook.paseto.service.Token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;


public class CurrentlyValid implements Claim {
	public final static String NAME = "CURRENTLY_VALID";
	public final static Duration DEFAULT_ALLOWABLE_DRIFT = Duration.ofSeconds(1);

	private final OffsetDateTime time;
	private final Duration allowableDrift;
	private final boolean allowWithoutExpiration;

	/**
	 * Verifies that the token is not expired or validated before it's "Not Before" time.
	 *
	 * This call sets the "check time" to Clock.systemUTC() and should be used in most cases.
	 *
	 * This constructor sets the allowable clock drift as DEFAULT_ALLOWABLE_DRIFT which is defined as 1 second. This
	 * relaxes the check by adding a 1 second window into the future during which the not before check will pass.
	 */
	public CurrentlyValid() {
		this(DEFAULT_ALLOWABLE_DRIFT, false);
	}

	/**
	 * Verifies that the token is not expired or validated before it's "Not Before" time.
	 *
	 * This call sets the "check time" to Clock.systemUTC() and should be used in most cases.
	 *
	 * This constructor sets the allowable clock drift as DEFAULT_ALLOWABLE_DRIFT which is defined as 1 second. This
	 * relaxes the check by adding a 1 second window into the future during which the not before check will pass.
	 * @param allowWithoutExpiration When true, treat tokens without a set expiry as valid.
	 */
	public CurrentlyValid(boolean allowWithoutExpiration) {
		this(DEFAULT_ALLOWABLE_DRIFT, allowWithoutExpiration);
	}

	/**
	 * Verifies that the token is not expired or validated before it's "Not Before" time.
	 *
	 * This call sets the "check time" to Clock.systemUTC() and should be used in most cases.
	 *
	 * @param allowableDrift Time window during which a token is considered valid even if it's not before time is in
	 * the future. Should be set to a small time window (default is 1 second) which allows for a
	 * slight clock drift between servers. Only applies to "not before" and not the expiration
	 * time.
	 */
	public CurrentlyValid(Duration allowableDrift) {
		this(null, allowableDrift, false);
	}

	/**
	 * Verifies that the token is not expired or validated before it's "Not Before" time.
	 *
	 * This call sets the "check time" to Clock.systemUTC() and should be used in most cases.
	 *
	 * @param allowableDrift Time window during which a token is considered valid even if it's not before time is in
	 * the future. Should be set to a small time window (default is 1 second) which allows for a
	 * slight clock drift between servers. Only applies to "not before" and not the expiration
	 * time.
	 * @param allowWithoutExpiration When true, treat tokens without a set expiry as valid.
	 */
	public CurrentlyValid(Duration allowableDrift, boolean allowWithoutExpiration) {
		this(null, allowableDrift, allowWithoutExpiration);
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
	 * the future. Should be set to a small time window (default is 1 second) which allows for a
	 * slight clock drift between servers. Only applies to "not before" and not the expiration
	 * time.
	 * @param allowWithoutExpiration When true, treat tokens without a set expiry as valid.
	 */
	public CurrentlyValid(OffsetDateTime time, Duration allowableDrift, boolean allowWithoutExpiration) {
		this.time = time;
		this.allowableDrift = allowableDrift;
		this.allowWithoutExpiration = allowWithoutExpiration;
	}

	@Override
	public String name() {
		return NAME;
	}

	@Override
	public void check(Token token, VerificationContext context) {
		// Note: issued at times can be checked with the IssuedInPast rule.
		OffsetDateTime time = this.time == null ? OffsetDateTime.now(Clock.systemUTC()) : this.time;

		// Check "Not Before" if provided.
		if (token.getNotBefore() != null) {
			OffsetDateTime notBefore = Instant.ofEpochSecond(token.getNotBefore()).atOffset(ZoneOffset.UTC);

			if (notBefore.minus(allowableDrift).isAfter(time)) {
				throw new NotYetValidTokenException(notBefore, NAME, token);
			}
		}

		// If no expiry time was set, then we treat the token as expired unless allowWithoutExpiration is true.
		if (token.getExpiration() == null) {
			if (allowWithoutExpiration) {
				return; // valid
			} else {
				throw new MissingClaimException(Token.CLAIM_EXPIRATION, NAME, token);
			}
		}

		OffsetDateTime expiration = Instant.ofEpochSecond(token.getExpiration()).atOffset(ZoneOffset.UTC);

		// Finally we check the expiration time.
		if (expiration.isBefore(time)) {
			throw new ExpiredTokenException(expiration, NAME, token);
		}
	}
}
