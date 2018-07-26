package net.aholbrook.paseto.crypto;

import java.util.Arrays;

public class KeyPair {
	private final byte[] secretKey, publicKey;

	public KeyPair(byte[] secretKey, byte[] publicKey) {
		this.secretKey = secretKey;
		this.publicKey = publicKey;
	}

	public byte[] getSecretKey() {
		return secretKey;
	}

	public byte[] getPublicKey() {
		return publicKey;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		KeyPair keyPair = (KeyPair) o;
		return Arrays.equals(secretKey, keyPair.secretKey) &&
				Arrays.equals(publicKey, keyPair.publicKey);
	}

	@Override
	public int hashCode() {

		int result = Arrays.hashCode(secretKey);
		result = 31 * result + Arrays.hashCode(publicKey);
		return result;
	}
}
