package net.aholbrook.paseto.claims;

import net.aholbrook.paseto.exception.claims.IncorrectIssuerException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.util.StringUtils;

public class IssuedBy implements Claim {
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
	public void check(Token token, VerificationContext context) {
		if (StringUtils.isEmpty(token.getIssuer())) {
			throw new MissingClaimException(Token.CLAIM_ISSUER, NAME, token);
		}

		if (!issuer.equals(token.getIssuer())) {
			throw new IncorrectIssuerException(issuer, token.getIssuer(), NAME, token);
		}
	}
}
