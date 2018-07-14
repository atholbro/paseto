package net.aholbrook.paseto.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.exception.verification.rules.IncorrectIssuerException;
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
		String tokenIssuer = StringUtils.ntes(token.getIssuer());

		if (!issuer.equals(tokenIssuer)) {
			throw new IncorrectIssuerException(issuer, token.getIssuer(), NAME, token);
		}
	}
}
