package net.aholbrook.paseto.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.exception.verification.rules.IncorrectSubjectException;
import net.aholbrook.paseto.util.StringUtils;
import net.aholbrook.paseto.verification.PasetoVerificationContext;

public class HasSubject implements Rule {
	public final static String NAME = "HAS_SUBJECT";

	private final String subject;

	/**
	 * Verifies that the token Subject (sub) claim matches the given value.
	 * @param subject The expected subject for the token.
	 */
	public HasSubject(String subject) {
		this.subject = StringUtils.ntes(subject);
	}

	@Override
	public String name() {
		return NAME;
	}

	@Override
	public void check(Token token, PasetoVerificationContext context) {
		String tokenSubject = StringUtils.ntes(token.getSubject());

		if (!subject.equals(tokenSubject)) {
			throw new IncorrectSubjectException(subject, token.getSubject(), NAME, token);
		}
	}
}
