package net.aholbrook.paseto.data;

import net.aholbrook.paseto.keys.AsymmetricPublicKey;
import net.aholbrook.paseto.keys.AsymmetricSecretKey;
import net.aholbrook.paseto.keys.SymmetricKey;

public class TestVector<_Payload, _Footer> {
	private final SymmetricKey localKey;
	private final AsymmetricSecretKey secretKey;
	private final AsymmetricPublicKey publicKey;
	private final byte[] nonce;
	private final _Payload payload;
	private final Class<_Payload> payloadClass;
	private final _Footer footer;
	private final String token;

	public TestVector(SymmetricKey localKey, byte[] nonce, _Payload payload, Class<_Payload> payloadClass,
					  _Footer footer, String token) {
		this.localKey = localKey;
		this.nonce = nonce;
		this.secretKey = null;
		this.publicKey = null;
		this.payload = payload;
		this.payloadClass = payloadClass;
		this.footer = footer;
		this.token = token;
	}

	public TestVector(AsymmetricSecretKey secretKey, AsymmetricPublicKey publicKey, _Payload payload,
					  Class<_Payload> payloadClass, _Footer footer, String token) {
		this.localKey = null;
		this.nonce = null;
		this.secretKey = secretKey;
		this.publicKey = publicKey;
		this.payload = payload;
		this.payloadClass = payloadClass;
		this.footer = footer;
		this.token = token;
	}

	public SymmetricKey getLocalKey() {
		return localKey;
	}

	public AsymmetricSecretKey getSecretKey() {
		return secretKey;
	}

	public AsymmetricPublicKey getPublicKey() {
		return publicKey;
	}

	public byte[] getNonce() {
		return nonce;
	}

	public _Payload getPayload() {
		return payload;
	}

	public Class<_Payload> getPayloadClass() {
		return payloadClass;
	}

	public _Footer getFooter() {
		return footer;
	}

	public String getToken() {
		return token;
	}
}
