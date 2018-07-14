package net.aholbrook.paseto.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.exception.verification.rules.IncorrectSubjectException;
import net.aholbrook.paseto.exception.verification.rules.MissingClaimException;
import net.aholbrook.paseto.util.StringUtils;
import net.aholbrook.paseto.verification.PasetoVerificationContext;

public class WithSubject implements Rule {
	public final static String NAME = "HAS_SUBJECT";

	private final String subject;

	/**
	 * Verifies that the token Subject (sub) claim matches the given value.
	 * @param subject The expected subject for the token.
	 */
	public WithSubject(String subject) {
		this.subject = StringUtils.ntes(subject);
	}

	@Override
	public String name() {
		return NAME;
	}

	@Override
	public void check(Token token, PasetoVerificationContext context) {
		if (StringUtils.isEmpty(token.getSubject())) {
			throw new MissingClaimException(Token.CLAIM_SUBJECT, NAME, token);
		}

		if (!subject.equals(token.getSubject())) {
			throw new IncorrectSubjectException(subject, token.getSubject(), NAME, token);
		}
	}
}
