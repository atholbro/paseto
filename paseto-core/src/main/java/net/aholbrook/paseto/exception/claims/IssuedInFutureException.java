package net.aholbrook.paseto.exception.claims;

import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.time.OffsetDateTime;

public class IssuedInFutureException extends ClaimException {
	public IssuedInFutureException(OffsetDateTime checkTime, OffsetDateTime issuedAt, String ruleName, Token token) {
		super(message(checkTime, issuedAt), ruleName, token);
	}

	private static String message(OffsetDateTime checkTime, OffsetDateTime issuedAt) {
		return "Token was issued at a future date/time " + issuedAt.toString() + ", currently: " + checkTime.toString();
	}
}
