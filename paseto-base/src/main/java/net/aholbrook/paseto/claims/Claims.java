package net.aholbrook.paseto.claims;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.exception.claims.ClaimException;
import net.aholbrook.paseto.exception.claims.MultipleClaimException;

import java.util.function.Function;

public class Claims {
	public static final ClaimCheck[] DEFAULT_CLAIM_CHECKS = new ClaimCheck[] {
			new IssuedInPast(), new CurrentlyValid()
	};

	public static VerificationContext verify(Token token) {
		return verify(token, DEFAULT_CLAIM_CHECKS);
	}

	public static VerificationContext verify(Token token, ClaimCheck[] claimChecks) {
		VerificationContext context = new VerificationContext(token);
		MultipleClaimException mre = new MultipleClaimException(token);

		for (ClaimCheck claimCheck : claimChecks) {
			try {
				claimCheck.check(token, context);
			} catch (ClaimException re) {
				mre.add(re);
			}
		}

		mre.throwIfNotEmpty();
		return context;
	}

	public static <_ReturnType> _ReturnType verify(Token token, Function<VerificationContext, _ReturnType> callback) {
		VerificationContext context = verify(token);
		return callback.apply(context);
	}

	public static <_ReturnType> _ReturnType verify(Token token, ClaimCheck[] claimChecks,
			Function<VerificationContext, _ReturnType> callback) {
		VerificationContext context = verify(token, claimChecks);
		return callback.apply(context);
	}
}
