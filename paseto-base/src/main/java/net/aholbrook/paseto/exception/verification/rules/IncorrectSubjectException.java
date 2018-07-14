package net.aholbrook.paseto.exception.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.util.StringUtils;

public class IncorrectSubjectException extends RuleException {
	private final String expected, subject;

	public IncorrectSubjectException(String expected, String subject, String ruleName, Token token) {
		super(message(expected, subject), ruleName, token);
		this.expected = expected;
		this.subject = subject;
	}

	public String getExpected() {
		return expected;
	}

	public String getSubject() {
		return subject;
	}

	private static String message(String expected, String subject) {
		return "Token subject is \"" + StringUtils.ntes(subject) + "\", required: \"" + expected + '"';
	}
}
