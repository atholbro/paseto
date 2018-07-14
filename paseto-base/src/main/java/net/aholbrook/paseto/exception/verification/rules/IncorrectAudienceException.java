package net.aholbrook.paseto.exception.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.util.StringUtils;

public class IncorrectAudienceException extends RuleException {
	private final String expected, audience;

	public IncorrectAudienceException(String expected, String audience, String ruleName, Token token) {
		super(message(expected, audience), ruleName, token);
		this.expected = expected;
		this.audience = audience;
	}

	public String getExpected() {
		return expected;
	}

	public String getAudience() {
		return audience;
	}

	private static String message(String expected, String subject) {
		return "Token audience is \"" + StringUtils.ntes(subject) + "\", required: \"" + expected + '"';
	}
}
