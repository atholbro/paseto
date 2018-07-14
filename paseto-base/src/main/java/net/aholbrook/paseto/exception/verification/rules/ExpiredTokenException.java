package net.aholbrook.paseto.exception.verification.rules;

import net.aholbrook.paseto.Token;

import java.time.OffsetDateTime;

public class ExpiredTokenException extends RuleException {
	private final Reason reason;

	public ExpiredTokenException(Reason reason, OffsetDateTime time, String ruleName, Token token) {
		super(message(reason, time), ruleName, token);
		this.reason = reason;
	}

	public Reason getReason() {
		return reason;
	}

	public enum Reason {
		NOT_YET_VALID,
		EXPIRED
	}

	private static String message(Reason reason, OffsetDateTime time) {
		switch (reason) {
			default:
				return "--missing switch branch--";
			case NOT_YET_VALID:
				return "Token is not valid until " + time.toString() + '.';
			case EXPIRED:
				return "Token expired at " + time.toString() + '.';
		}
	}
}
