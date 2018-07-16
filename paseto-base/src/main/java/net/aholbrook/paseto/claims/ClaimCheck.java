package net.aholbrook.paseto.claims;

import net.aholbrook.paseto.service.Token;

public interface ClaimCheck {
	/**
	 * Name of the check.
	 * @return rule name
	 */
	String name();

	/**
	 * Verify that the given token passes the this rule.
	 * @param token Token to check.
	 * @param context Claims context to store additional data.
	 */
	void check(Token token, VerificationContext context);
}
