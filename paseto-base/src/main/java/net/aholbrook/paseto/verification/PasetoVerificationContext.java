package net.aholbrook.paseto.verification;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.util.StringUtils;

import java.util.HashSet;
import java.util.Set;

public class PasetoVerificationContext {
	private final Token token;
	private final Set<String> verifiedClaims = new HashSet<>();

	public PasetoVerificationContext(Token token) {
		this.token = token;
	}

	public Token getToken() {
		return token;
	}

	public Set<String> getVerifiedClaims() {
		return verifiedClaims;
	}

	public boolean hasClaim(String name) {
		if (StringUtils.isEmpty(name)) { return false; }
		return verifiedClaims.contains(name);
	}
}
