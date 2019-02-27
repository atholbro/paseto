package net.aholbrook.paseto.exception.claims;

import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.time.OffsetDateTime;

public class ExpiredTokenException extends ClaimException {
	public ExpiredTokenException(OffsetDateTime time, String ruleName, Token token) {
		super(message(time), ruleName, token);
	}

	private static String message(OffsetDateTime time) {
		return "Token expired at " + time.toString() + '.';
	}
}
