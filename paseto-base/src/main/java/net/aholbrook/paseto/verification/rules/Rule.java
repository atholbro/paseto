package net.aholbrook.paseto.verification.rules;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.verification.PasetoVerificationContext;

public interface Rule {
	/**
	 * Name of the rule.
	 * @return rule name
	 */
	String name();

	/**
	 * Verify that the given token passes the this validation rule.
	 * @param token Token to check.
	 * @param context PasetoVerification context to store additional data.
	 */
	void check(Token token, PasetoVerificationContext context);
}
