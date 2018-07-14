package net.aholbrook.paseto.exception.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.util.StringUtils;

public class IncorrectIssuerException extends RuleException {
	private final String expected, issuer;

	public IncorrectIssuerException(String expected, String issuer, String ruleName, Token token) {
		super(message(expected, issuer), ruleName, token);
		this.expected = expected;
		this.issuer = issuer;
	}

	public String getExpected() {
		return expected;
	}

	public String getIssuer() {
		return issuer;
	}

	private static String message(String expected, String issuer) {
		return "Token issued by \"" + StringUtils.ntes(issuer) + "\", required: \"" + expected + '"';
	}
}
