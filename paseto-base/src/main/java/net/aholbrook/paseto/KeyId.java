package net.aholbrook.paseto;

import java.util.Objects;

public class KeyId {
	public final static String CLAIM_KEY_ID = "KEY_ID";

	// Standard name from the RFC. Using this name should lead to correct serialization with GSON.
	// Jackson requires the use of a mixin since it reads the getter/setter.
	private String kid;

	public String getKeyId() {
		return kid;
	}

	public KeyId setKeyId(String keyId) {
		this.kid = keyId;
		return this;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		KeyId keyId = (KeyId) o;
		return Objects.equals(kid, keyId.kid);
	}

	@Override
	public int hashCode() {
		return Objects.hash(kid);
	}

	@Override
	public String toString() {
		return "KeyId{"
				+ "kid='" + kid + '\''
				+ '}';
	}
}
