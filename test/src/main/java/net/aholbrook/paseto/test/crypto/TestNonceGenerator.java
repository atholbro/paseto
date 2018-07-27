package net.aholbrook.paseto.test.crypto;

import net.aholbrook.paseto.crypto.NonceGenerator;

public class TestNonceGenerator implements NonceGenerator {
	private final byte[] nonce;

	public TestNonceGenerator(byte[] nonce) {
		this.nonce = nonce;
	}

	@Override
	public byte[] generateNonce() {
		return nonce;
	}
}
