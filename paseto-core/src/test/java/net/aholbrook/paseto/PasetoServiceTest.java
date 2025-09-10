package net.aholbrook.paseto;

import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.crypto.TestNonceGenerator;
import net.aholbrook.paseto.data.RfcToken;
import net.aholbrook.paseto.data.TestVector;
import net.aholbrook.paseto.exception.claims.ExpiredTokenException;
import net.aholbrook.paseto.exception.claims.IssuedInFutureException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.utils.AssertUtils;
import org.junit.jupiter.api.Assertions;

import java.time.OffsetDateTime;

public abstract class PasetoServiceTest {
	protected abstract LocalTokenService.KeyProvider rfcLocalKeyProvider();
	protected abstract PublicTokenService.KeyProvider rfcPublicKeyProvider();
	protected abstract LocalTokenService.KeyProvider tokenLocalKeyProvider();
	protected abstract PublicTokenService.KeyProvider tokenPublicKeyProvider();

	protected TokenService<RfcToken> rfcLocalService(Paseto.Builder builder, byte[] nonce) {
		LocalTokenService.Builder<RfcToken> serviceBuilder
				= new LocalTokenService.Builder<>(RfcToken.class, rfcLocalKeyProvider())
				.checkClaims(new Claim[] {});

		if (nonce == null) {
			serviceBuilder.withPaseto(builder.build());
		} else {
			serviceBuilder.withPaseto(builder.withNonceGenerator(new TestNonceGenerator(nonce)).build());
		}

		return serviceBuilder.build();
	}

	protected TokenService<RfcToken> rfcPublicService(Paseto.Builder builder) {
		return new PublicTokenService.Builder<>(RfcToken.class, rfcPublicKeyProvider())
				.checkClaims(new Claim[] {})
				.withPaseto(builder.build())
				.build();
	}

	protected TokenService<Token> tokenLocalService(Paseto.Builder builder, byte[] nonce) {
		LocalTokenService.Builder<Token> serviceBuilder
				= new LocalTokenService.Builder<>(Token.class, tokenLocalKeyProvider())
				.checkClaims(new Claim[] {});

		if (nonce == null) {
			serviceBuilder.withPaseto(builder.build());
		} else {
			serviceBuilder.withPaseto(builder.withNonceGenerator(new TestNonceGenerator(nonce)).build());
		}

		return serviceBuilder.build();
	}

	protected TokenService<Token> tokenPublicService(Paseto.Builder builder) {
		return new PublicTokenService.Builder<>(Token.class, tokenPublicKeyProvider())
				.checkClaims(new Claim[] {})
				.withPaseto(builder.build())
				.build();
	}

	<_TokenType extends Token, _Footer> void encodeTestVector(TokenService<_TokenType> tokenService,
			TestVector<_TokenType, _Footer> tv) {
		Assertions.assertNotNull(tokenService, "paseto token service");

		String encoded;
		if (tv.getFooter() != null) {
			encoded = tokenService.encode(tv.getPayload(), tv.getFooter());
		} else {
			encoded = tokenService.encode(tv.getPayload());
		}

		Assertions.assertEquals(tv.getToken(), encoded, "Generated token does not match test vector.");
	}

	<_TokenType extends Token, _Footer> void encodeDecodeTestVector(TokenService<_TokenType> tokenService,
			TestVector<_TokenType, _Footer> tv) {
		Assertions.assertNotNull(tokenService, "paseto token service");

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

		Assertions.assertEquals(tv.getPayload(), payload, "Decoded payload does not match test vector.");
	}

	<_TokenType extends Token, _Footer> void decodeTestVector(TokenService<_TokenType> tokenService,
			TestVector<_TokenType, _Footer> tv) {
		Assertions.assertNotNull(tokenService, "paseto token service");

		_TokenType payload;
		if (tv.getFooter() != null) {
			payload = tokenService.decode(tv.getToken(), tv.getFooter());
		} else {
			payload = tokenService.decode(tv.getToken());
		}

		Assertions.assertEquals(tv.getPayload(), payload, "Decoded token does not match test vector.");
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
			Assertions.fail("Failed to catch expected MissingClaimException.");
		} catch (MissingClaimException e) { /* ignore */ }

		// Decode expired token
		try {
			checkExpired(service);
			Assertions.fail("Failed to catch expected ExpiredTokenException.");
		} catch (ExpiredTokenException e) { /* ignore */ }

		// Decode token issued in the future
		try {
			checkIssuedInFuture(service);
			Assertions.fail("Failed to catch expected IssuedInFutureException.");
		} catch (IssuedInFutureException e) { /* ignore */ }
	}

	void checkOnlyCurrentlyValid(TokenService<Token> service) {
		// This should have only CurrentlyValid claim
		// So encoding without a expiry should result in an error
		try {
			checkWithoutExpiry(service);
			Assertions.fail("Failed to catch expected MissingClaimException.");
		} catch (MissingClaimException e) { /* ignore */ }

		// Decoding an expired token should also result in an error
		try {
			checkExpired(service);
			Assertions.fail("Failed to catch expected ExpiredTokenException.");
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
			Assertions.fail("Failed to catch expected ExpiredTokenException.");
		} catch (ExpiredTokenException e) { /* ignore */ }

		// And decoding a token issued in the future should fail too:
		try {
			checkIssuedInFuture(service);
			Assertions.fail("Failed to catch expected IssuedInFutureException.");
		} catch (IssuedInFutureException e) { /* ignore */ }
	}

	void checkOnlyCurrentlyValidWithValidity(TokenService<Token> service) {
		// This should have a defaultValidity set
		// So encoding without a expiry should work, as the default will be used
		checkWithoutExpiry(service);

		// Decoding an expired token should result in an error
		try {
			checkExpired(service);
			Assertions.fail("Failed to catch expected ExpiredTokenException.");
		} catch (ExpiredTokenException e) { /* ignore */ }

		// But decoding a token issued in the future should work just fine
		checkIssuedInFuture(service);
	}
}
