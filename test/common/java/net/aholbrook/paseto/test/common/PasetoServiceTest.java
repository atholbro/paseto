package net.aholbrook.paseto.test.common;

import net.aholbrook.paseto.exception.claims.ExpiredTokenException;
import net.aholbrook.paseto.exception.claims.IssuedInFutureException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.test.common.data.TestVector;
import net.aholbrook.paseto.test.common.utils.AssertUtils;
import net.aholbrook.paseto.time.OffsetDateTime;

import org.junit.Assert;

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
		token.setIssuedAt(OffsetDateTime.now().minusMinutes(1).toEpochSecond());
		token.setExpiration(OffsetDateTime.now().minusSeconds(1).toEpochSecond());

		service.decode(service.encode(token));
	}

	void checkIssuedInFuture(TokenService<Token> service) {
		Token token = new Token().setTokenId("id");
		token.setIssuedAt(OffsetDateTime.now().plusMinutes(1).toEpochSecond());
		token.setExpiration(OffsetDateTime.now().plusMinutes(5).toEpochSecond());
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
