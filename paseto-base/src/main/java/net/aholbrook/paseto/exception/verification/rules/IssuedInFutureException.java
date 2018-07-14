package net.aholbrook.paseto.exception.verification.rules;

import net.aholbrook.paseto.Token;

import java.time.OffsetDateTime;

public class IssuedInFutureException extends RuleException {
	public IssuedInFutureException(OffsetDateTime checkTime, OffsetDateTime issuedAt, String ruleName, Token token) {
		super(message(checkTime, issuedAt), ruleName, token);
	}

	private static String message(OffsetDateTime checkTime, OffsetDateTime issuedAt) {
		return "Token was issued at a future date/time " + issuedAt.toString() + ", currently: " + checkTime.toString();
	}
}
