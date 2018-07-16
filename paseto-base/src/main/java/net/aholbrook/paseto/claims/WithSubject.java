package net.aholbrook.paseto.claims;

import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.exception.claims.IncorrectSubjectException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.util.StringUtils;

public class WithSubject implements ClaimCheck {
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
	public void check(Token token, VerificationContext context) {
		if (StringUtils.isEmpty(token.getSubject())) {
			throw new MissingClaimException(Token.CLAIM_SUBJECT, NAME, token);
		}

		if (!subject.equals(token.getSubject())) {
			throw new IncorrectSubjectException(subject, token.getSubject(), NAME, token);
		}
	}
}
