/*
Copyright 2018 Andrew Holbrook

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package net.aholbrook.paseto.test.data;

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
