package net.aholbrook.paseto.exception.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.exception.PasetoTokenException;

public class RuleException extends PasetoTokenException {
	private final String ruleName;

	public RuleException(String s, String ruleName, Token token) {
		super(s, token);
		this.ruleName = ruleName;
	}

	public RuleException(String s, String ruleName, Token token, Throwable throwable) {
		super(s, token, throwable);
		this.ruleName = ruleName;
	}

	public String getRuleName() {
		return ruleName;
	}
}
