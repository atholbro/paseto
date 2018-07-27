package net.aholbrook.paseto.claims;

import net.aholbrook.paseto.exception.claims.ClaimException;
import net.aholbrook.paseto.exception.claims.MultipleClaimException;
import net.aholbrook.paseto.service.Token;

public class Claims {
	private Claims() {}

	public static final Claim[] DEFAULT_CLAIM_CHECKS = new Claim[] {
			new IssuedInPast(), new CurrentlyValid()
	};

	public static VerificationContext verify(Token token) {
		return verify(token, DEFAULT_CLAIM_CHECKS);
	}

	public static VerificationContext verify(Token token, Claim[] claims) {
		VerificationContext context = new VerificationContext(token);
		MultipleClaimException mre = new MultipleClaimException(token);

		for (Claim claim : claims) {
			try {
				claim.check(token, context);
				context.addVerifiedClaim(claim.name());
			} catch (ClaimException re) {
				mre.add(re);
			}
		}

		mre.throwIfNotEmpty();
		return context;
	}
}
