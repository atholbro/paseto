package net.aholbrook.paseto.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.exception.verification.rules.IssuedInFutureException;
import net.aholbrook.paseto.exception.verification.rules.MissingClaimException;
import net.aholbrook.paseto.verification.PasetoVerificationContext;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;

public class IssuedInPast implements Rule {
	public final static String NAME = "ISSUED_IN_PAST";
	public final static Duration DEFAULT_ALLOWABLE_DRIFT = Duration.ofSeconds(1);

	private final OffsetDateTime time;
	private final Duration allowableDrift;

	/**
	 * Ensures that the token was issued in the past.
	 *
	 * If a token was issued in the future, then it's likely that either the issuer clock is running fast, or that our
	 * clock is running slow. In either case our expiry checks will be unreliable and in most cases you should treat the
	 * token as invalid.
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
	 * clock is running slow. In either case our expiry checks will be unreliable and in most cases you should treat the
	 * token as invalid.
	 *
	 * This call sets the "check time" to Clock.systemUTC() and should be used in most cases.
	 */
	public IssuedInPast(Duration allowableDrift) {
		this(OffsetDateTime.now(Clock.systemUTC()), allowableDrift);
	}

	/**
	 * Ensures that the token was issued in the past.
	 *
	 * If a token was issued in the future, then it's likely that either the issuer clock is running fast, or that our
	 * 	 * clock is running slow. In either case our expiry checks will be unreliable and in most cases you should treat the
	 * 	 * token as invalid.
	 *
	 * This constructor allows the caller to specify the instant ("NOW") at which to check. It's intended
	 * for unit testing and edge cases. In most cases you should use the no argument constructor which uses the
	 * current UTC system time.
	 * @param time The time used for validity checks.
	 * @param allowableDrift Maximum allowable clock drift between our time and the issued time. Allows for a small
	 *                       window of clock drift between servers. Default is DEFAULT_ALLOWABLE_DRIFT(1 second).
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
	public void check(Token token, PasetoVerificationContext context) {
		if (token.getIssuedAt() == null) {
			throw new MissingClaimException(Token.CLAIM_ISSUED_AT, NAME, token);
		}

		Duration difference = Duration.between(token.getIssuedAt(), time);
		if (difference.compareTo(allowableDrift) < 0) {
			throw new IssuedInFutureException(time, token.getIssuedAt(), NAME, token);
		}
	}
}
