package net.aholbrook.paseto.exception.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.util.StringUtils;

public class MissingClaimException extends RuleException {
	private final String claim;

	public MissingClaimException(String claim, String ruleName, Token token) {
		super(message(claim), ruleName, token);
		this.claim = claim;
	}

	public String getClaim() {
		return claim;
	}

	private static String message(String claim) {
		return "Token is missing required claim " + StringUtils.ntes(claim) + '.';
	}
}
