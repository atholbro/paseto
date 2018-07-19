package net.aholbrook.paseto.exception.claims;

import net.aholbrook.paseto.service.Token;

import java.time.OffsetDateTime;

public class NotYetValidTokenException extends ClaimException {
	public NotYetValidTokenException(OffsetDateTime time, String ruleName, Token token) {
		super(message( time), ruleName, token);
	}

	private static String message(OffsetDateTime time) {
		return "Token is not valid until " + time.toString() + '.';
	}
}
