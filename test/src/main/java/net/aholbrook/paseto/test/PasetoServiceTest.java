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

import net.aholbrook.paseto.exception.claims.ExpiredTokenException;
import net.aholbrook.paseto.exception.claims.IssuedInFutureException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.test.data.TestVector;
import net.aholbrook.paseto.test.utils.AssertUtils;
import org.junit.Assert;

import java.time.OffsetDateTime;

public abstract class PasetoServiceTest {
	<_TokenType extends Token, _Footer> void encodeTestVector(TokenService<_TokenType> tokenService,
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

	<_TokenType extends Token, _Footer> void encodeDecodeTestVector(TokenService<_TokenType> tokenService,
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

	<_TokenType extends Token, _Footer> void decodeTestVector(TokenService<_TokenType> tokenService,
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

	void checkWithoutExpiry(TokenService<Token> service) {
		Token token = new Token().setTokenId("id");
		AssertUtils.assertMissingClaimException(() ->
				service.encode(token), "TokenService", token, Token.CLAIM_EXPIRATION);
	}

	void checkExpired(TokenService<Token> service) {
		Token token = new Token().setTokenId("id");
		token.setIssuedAt(OffsetDateTime.now().minusMinutes(1));
		token.setExpiration(OffsetDateTime.now().minusSeconds(1));

		service.decode(service.encode(token));
	}

	void checkIssuedInFuture(TokenService<Token> service) {
		Token token = new Token().setTokenId("id");
		token.setIssuedAt(OffsetDateTime.now().plusMinutes(1));
		token.setExpiration(OffsetDateTime.now().plusMinutes(5));
		service.decode(service.encode(token));
	}

	void checkDefault(TokenService<Token> service) {
		// Default should have the default claim checks and no default expiry, so these should all fail:
		// Encode without expiry time
		try {
			checkWithoutExpiry(service);
			Assert.fail("Failed to catch expected MissingClaimException.");
		} catch (MissingClaimException e) { /* ignore */ }

		// Decode expired token
		try {
			checkExpired(service);
			Assert.fail("Failed to catch expected ExpiredTokenException.");
		} catch (ExpiredTokenException e) { /* ignore */ }

		// Decode token issued in the future
		try {
			checkIssuedInFuture(service);
			Assert.fail("Failed to catch expected IssuedInFutureException.");
		} catch (IssuedInFutureException e) { /* ignore */ }
	}

	void checkOnlyCurrentlyValid(TokenService<Token> service) {
		// This should have only CurrentlyValid claim
		// So encoding without a expiry should result in an error
		try {
			checkWithoutExpiry(service);
			Assert.fail("Failed to catch expected MissingClaimException.");
		} catch (MissingClaimException e) { /* ignore */ }

		// Decoding an expired token should also result in an error
		try {
			checkExpired(service);
			Assert.fail("Failed to catch expected ExpiredTokenException.");
		} catch (ExpiredTokenException e) { /* ignore */ }

		// But decoding a token issued in the future should work just fine
		checkIssuedInFuture(service);
	}

	void checkDefaultWithValidity(TokenService<Token> service) {
		// This should have a defaultValidity set
		// So encoding without a expiry should work, as the default will be used
		checkWithoutExpiry(service);

		// Decoding an expired token should result in an error
		try {
			checkExpired(service);
			Assert.fail("Failed to catch expected ExpiredTokenException.");
		} catch (ExpiredTokenException e) { /* ignore */ }

		// And decoding a token issued in the future should fail too:
		try {
			checkIssuedInFuture(service);
			Assert.fail("Failed to catch expected IssuedInFutureException.");
		} catch (IssuedInFutureException e) { /* ignore */ }
	}

	void checkOnlyCurrentlyVaildWithValidity(TokenService<Token> service) {
		// This should have a defaultValidity set
		// So encoding without a expiry should work, as the default will be used
		checkWithoutExpiry(service);

		// Decoding an expired token should result in an error
		try {
			checkExpired(service);
			Assert.fail("Failed to catch expected ExpiredTokenException.");
		} catch (ExpiredTokenException e) { /* ignore */ }

		// But decoding a token issued in the future should work just fine
		checkIssuedInFuture(service);
	}
}
