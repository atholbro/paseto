package net.aholbrook.paseto.claims;

import net.aholbrook.paseto.exception.claims.IssuedInFutureException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.service.Token;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;

public class IssuedInPast implements Claim {
	public final static String NAME = "ISSUED_IN_PAST";
	public final static Duration DEFAULT_ALLOWABLE_DRIFT = Duration.ofSeconds(1);

	private final OffsetDateTime time;
	private final Duration allowableDrift;

	/**
	 * Ensures that the token was issued in the past.
	 *
	 * If a token was issued in the future, then it's likely that either the issuer clock is running fast, or that our
	 * clock is running slow. In either case our expiry not before check will be unreliable and in most cases you should
	 * treat the token as invalid.
	 *
	 * This constructor sets the allowable clock drift as DEFAULT_ALLOWABLE_DRIFT which is defined as 1 second. This
	 * relaxes the check by adding a 1 second window into the future during which this check will pass.
	 *
	 * This call sets the "check time" to Clock.systemUTC() and should be used in most cases.
	 */
	public IssuedInPast() {
		this(DEFAULT_ALLOWABLE_DRIFT);
	}

	/**
	 * Ensures that the token was issued in the past.
	 *
	 * If a token was issued in the future, then it's likely that either the issuer clock is running fast, or that our
	 * clock is running slow. In either case our expiry not before check will be unreliable and in most cases you should
	 * treat the token as invalid.
	 *
	 * This call sets the "check time" to Clock.systemUTC() and should be used in most cases.
	 *
	 * @param allowableDrift Time window during which a token is considered valid even if it was issued in the future.
	 * Should be set to a small time window (default is 1 second) which allows for a slight clock
	 * drift between servers.
	 */
	public IssuedInPast(Duration allowableDrift) {
		this(null, allowableDrift);
	}

	/**
	 * Ensures that the token was issued in the past.
	 *
	 * If a token was issued in the future, then it's likely that either the issuer clock is running fast, or that our
	 * clock is running slow. In either case our expiry not before check will be unreliable and in most cases you should
	 * treat the token as invalid.
	 *
	 * This constructor allows the caller to specify the instant ("NOW") at which to check. It's intended
	 * for unit testing and edge cases. In most cases you should use the no argument constructor which uses the
	 * current UTC system time.
	 *
	 * @param time The time used for validity checks.
	 * @param allowableDrift Time window during which a token is considered valid even if it was issued in the future.
	 * Should be set to a small time window (default is 1 second) which allows for a slight clock
	 * drift between servers.
	 */
	public IssuedInPast(OffsetDateTime time, Duration allowableDrift) {
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

		if (token.getIssuedAt() == null) {
			throw new MissingClaimException(Token.CLAIM_ISSUED_AT, NAME, token);
		}

		if (token.getIssuedAt().minus(allowableDrift).isAfter(time)) {
			throw new IssuedInFutureException(time, token.getIssuedAt(), NAME, token);
		}
	}
}
