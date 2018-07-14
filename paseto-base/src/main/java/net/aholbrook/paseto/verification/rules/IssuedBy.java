package net.aholbrook.paseto.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.exception.verification.rules.IncorrectIssuerException;
import net.aholbrook.paseto.exception.verification.rules.MissingClaimException;
import net.aholbrook.paseto.util.StringUtils;
import net.aholbrook.paseto.verification.PasetoVerificationContext;

public class IssuedBy implements Rule {
	public final static String NAME = "ISSUED_BY";

	private final String issuer;

	/**
	 * Verifies that the token Issuer (iss) claim matches the given value.
	 *
	 * @param issuer The expected issuer of the token.
	 */
	public IssuedBy(String issuer) {
		this.issuer = StringUtils.ntes(issuer);
	}

	@Override
	public String name() {
		return NAME;
	}

	@Override
	public void check(Token token, PasetoVerificationContext context) {
		if (StringUtils.isEmpty(token.getIssuer())) {
			throw new MissingClaimException(Token.CLAIM_ISSUER, NAME, token);
		}

		if (!issuer.equals(token.getIssuer())) {
			throw new IncorrectIssuerException(issuer, token.getIssuer(), NAME, token);
		}
	}
}
