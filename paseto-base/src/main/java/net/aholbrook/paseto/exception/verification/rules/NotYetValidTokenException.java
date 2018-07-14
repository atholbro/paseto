package net.aholbrook.paseto.exception.verification.rules;

import net.aholbrook.paseto.Token;

import java.time.OffsetDateTime;

public class NotYetValidTokenException extends RuleException {
	public NotYetValidTokenException(OffsetDateTime time, String ruleName, Token token) {
		super(message( time), ruleName, token);
	}

	private static String message(OffsetDateTime time) {
		return "Token is not valid until " + time.toString() + '.';
	}
}
