package net.aholbrook.paseto.crypto;

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
