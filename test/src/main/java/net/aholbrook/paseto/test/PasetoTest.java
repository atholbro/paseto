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

package net.aholbrook.paseto.test;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.exception.InvalidFooterException;
import net.aholbrook.paseto.exception.InvalidHeaderException;
import net.aholbrook.paseto.exception.PasetoStringException;
import net.aholbrook.paseto.test.data.TestVector;
import net.aholbrook.paseto.util.StringUtils;
import org.junit.Assert;

import java.nio.charset.Charset;

public abstract class PasetoTest {
	protected abstract <_TokenType> Paseto<_TokenType> createPaseto(byte[] nonce);

	protected <_TokenType, _Footer> void encryptTestVector(TestVector<_TokenType, _Footer> tv) {
		// A: key, B: nonce
		Paseto<_TokenType> paseto = createPaseto(tv.getB());
		Assert.assertNotNull("paseto V1 instance", paseto);

		String token;
		if (tv.getFooter() != null ) {
			token = paseto.encrypt(tv.getPayload(), tv.getA(), tv.getFooter());
		} else {
			token = paseto.encrypt(tv.getPayload(), tv.getA());
		}

		Assert.assertEquals("Generated token does not match test vector.", tv.getToken(), token);
	}

	protected <_TokenType, _Footer> void decryptTestVector(TestVector<_TokenType, _Footer> tv) {
		// A: key, B: nonce
		Paseto<_TokenType> paseto = createPaseto(tv.getB());
		Assert.assertNotNull("paseto V1 instance", paseto);

		_TokenType payload;
		if (tv.getFooter() != null ) {
			payload = paseto.decrypt(tv.getToken(), tv.getA(), tv.getFooter(),
					tv.getPayloadClass());
		} else {
			payload = paseto.decrypt(tv.getToken(), tv.getA(), tv.getPayloadClass());
		}

		Assert.assertEquals("Decrypted payload does not match test vector.", tv.getPayload(), payload);
	}

	protected <_TokenType, _Footer> void signTestVector(TestVector<_TokenType, _Footer> tv, boolean assertSigned) {
		// A: sk, B: pk
		Paseto<_TokenType> paseto = createPaseto(null);
		Assert.assertNotNull("paseto V1 instance", paseto);

		String token;
		if (tv.getFooter() != null ) {
			token = paseto.sign(tv.getPayload(), tv.getA(),
					tv.getFooter());
		} else {
			token = paseto.sign(tv.getPayload(), tv.getA());
		}

		if (assertSigned) {
			Assert.assertEquals("Generated token does not match test vector.", tv.getToken(), token);
		}

		// Now verify the signature (we can't use the token in the test vector as the signature will change each time.
		_TokenType decoded;
		if (tv.getFooter() != null ) {
			decoded = paseto.verify(token, tv.getB(), tv.getFooter(), tv.getPayloadClass());
		} else {
			decoded = paseto.verify(token, tv.getB(), tv.getPayloadClass());
		}

		Assert.assertEquals("Decoded payload does not match test vector.", tv.getPayload(), decoded);
	}

	protected <_TokenType, _Footer> void verifyTestVector(TestVector<_TokenType, _Footer> tv) {
		// A: sk, B: pk
		Paseto<_TokenType> paseto = createPaseto(null);
		Assert.assertNotNull("paseto V1 instance", paseto);

		_TokenType payload;
		if (tv.getFooter() != null ) {
			payload = paseto.verify(tv.getToken(), tv.getB(), tv.getFooter(), tv.getPayloadClass());
		} else {
			payload = paseto.verify(tv.getToken(), tv.getB(), tv.getPayloadClass());
		}

		Assert.assertEquals("Verified payload does not match test vector.", tv.getPayload(), payload);
	}

	protected String modify(String token, int[] indices) {
		byte[] tokenBytes = StringUtils.getBytesUtf8(token);
		for (int i : indices) {
			tokenBytes[i] ^= 1;
		}
		return new String(tokenBytes, Charset.forName("UTF-8"));
	}
}
