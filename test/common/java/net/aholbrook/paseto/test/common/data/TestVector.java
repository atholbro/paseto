package net.aholbrook.paseto.test.common.data;

public class TestVector<_Payload, _Footer> {
	private final byte[] a, b;
	private final _Payload payload;
	private final Class<_Payload> payloadClass;
	private final _Footer footer;
	private final String token;

	public TestVector(byte[] a, byte[] b, _Payload payload, Class<_Payload> payloadClass, _Footer footer,
			String token) {
		this.a = a;
		this.b = b;
		this.payload = payload;
		this.payloadClass = payloadClass;
		this.footer = footer;
		this.token = token;
	}

	public byte[] getA() {
		return a;
	}

	public byte[] getB() {
		return b;
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
