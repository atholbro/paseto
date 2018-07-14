package net.aholbrook.paseto.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.exception.verification.rules.IncorrectAudienceException;
import net.aholbrook.paseto.exception.verification.rules.MissingClaimException;
import net.aholbrook.paseto.util.StringUtils;
import net.aholbrook.paseto.verification.PasetoVerificationContext;

public class ForAudience implements Rule {
	public final static String NAME = "FOR_AUDIENCE";

	private final String audience;

	/**
	 * Verifies that the token Audience (aud) claim matches the given value.
	 * @param audience The expected audience for the token.
	 */
	public ForAudience(String audience) {
		this.audience = StringUtils.ntes(audience);
	}

	@Override
	public String name() {
		return NAME;
	}

	@Override
	public void check(Token token, PasetoVerificationContext context) {
		if (StringUtils.isEmpty(token.getAudience())) {
			throw new MissingClaimException(Token.CLAIM_AUDIENCE, NAME, token);
		}

		if (!audience.equals(token.getAudience())) {
			throw new IncorrectAudienceException(audience, token.getAudience(), NAME, token);
		}
	}
}
