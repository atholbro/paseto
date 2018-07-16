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

import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.test.data.RfcToken;
import net.aholbrook.paseto.test.data.TestVector;
import org.junit.Assert;

public abstract class PasetoServiceTestBase {
	protected abstract LocalTokenService.KeyProvider localKeyProvider();
	protected abstract PublicTokenService.KeyProvider publicKeyProvider();

	protected abstract TokenService<RfcToken> createRfcLocal(byte[] nonce);
	protected abstract TokenService<RfcToken> createRfcPublic();

	protected <_TokenType extends Token, _Footer> void encodeTestVector(TokenService<_TokenType> tokenService,
			TestVector<_TokenType, _Footer> tv) {
		Assert.assertNotNull("paseto token service", tokenService);

		String encoded;
		if (tv.getFooter() != null) {
			encoded = tokenService.encode(tv.getPayload(), tv.getFooter());
		} else {
			encoded = tokenService.encode(tv.getPayload());
		}

		Assert.assertEquals("Generated token does not match test vector.", tv.getToken(), encoded);
	}

	protected <_TokenType extends Token, _Footer> void encodeDecodeTestVector(TokenService<_TokenType> tokenService,
			TestVector<_TokenType, _Footer> tv) {
		Assert.assertNotNull("paseto token service", tokenService);

		String encoded;
		if (tv.getFooter() != null) {
			encoded = tokenService.encode(tv.getPayload(), tv.getFooter());
		} else {
			encoded = tokenService.encode(tv.getPayload());
		}

		_TokenType payload;
		if (tv.getFooter() != null) {
			payload = tokenService.decode(encoded, tv.getFooter());
		} else {
			payload = tokenService.decode(encoded);
		}

		Assert.assertEquals("Decoded payload does not match test vector.", tv.getPayload(), payload);
	}

	protected <_TokenType extends Token, _Footer> void decodeTestVector(TokenService<_TokenType> tokenService,
			TestVector<_TokenType, _Footer> tv) {
		Assert.assertNotNull("paseto token service", tokenService);

		_TokenType payload;
		if (tv.getFooter() != null) {
			payload = tokenService.decode(tv.getToken(), tv.getFooter());
		} else {
			payload = tokenService.decode(tv.getToken());
		}

		Assert.assertEquals("Decoded token does not match test vector.", tv.getPayload(), payload);
	}
}
