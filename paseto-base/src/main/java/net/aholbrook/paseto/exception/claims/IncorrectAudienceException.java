package net.aholbrook.paseto.exception.claims;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.util.StringUtils;

public class IncorrectAudienceException extends ClaimException {
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
