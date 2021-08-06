package net.aholbrook.paseto.keys;

public class KeyPair {
	private final AsymmetricSecretKey secretKey;
	private final AsymmetricPublicKey publicKey;

	public KeyPair(AsymmetricSecretKey secretKey, AsymmetricPublicKey publicKey) {
		this.secretKey = secretKey;
		this.publicKey = publicKey;
	}

	public AsymmetricSecretKey getSecretKey() {
		return secretKey;
	}

	public AsymmetricPublicKey getPublicKey() {
		return publicKey;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		KeyPair keyPair = (KeyPair) o;
		return secretKey.equals(keyPair.secretKey) &&
				publicKey.equals(keyPair.publicKey);
	}

	@Override
	public int hashCode() {
		int result = secretKey.hashCode();
		result = 31 * result + publicKey.hashCode();
		return result;
	}
}
