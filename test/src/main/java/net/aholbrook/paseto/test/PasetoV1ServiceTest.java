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
import net.aholbrook.paseto.PasetoV1;
import net.aholbrook.paseto.TokenWithFooter;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.CurrentlyValid;
import net.aholbrook.paseto.exception.claims.ExpiredTokenException;
import net.aholbrook.paseto.exception.claims.IssuedInFutureException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.test.data.RfcTestVectors;
import net.aholbrook.paseto.test.data.RfcToken;
import net.aholbrook.paseto.test.data.TestVector;
import net.aholbrook.paseto.test.utils.AssertUtils;
import net.aholbrook.paseto.test.utils.TestContext;
import org.junit.Assert;
import org.junit.Test;

import java.time.Duration;
import java.time.OffsetDateTime;

public class PasetoV1ServiceTest extends PasetoServiceTest {
	private static LocalTokenService.KeyProvider rfcLocalKeyProvider() {
		return () -> RfcTestVectors.RFC_TEST_KEY;
	}

	private static PublicTokenService.KeyProvider rfcPublicKeyProvider() {
		return new PublicTokenService.KeyProvider() {
			@Override
			public byte[] getSecretKey() {
				return RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY;
			}

			@Override
			public byte[] getPublicKey() {
				return RfcTestVectors.RFC_TEST_RSA_PUBLIC_KEY;
			}
		};
	}

	private static TokenService<RfcToken> rfcLocalService(byte[] nonce) {
		return TestContext.builders().localServiceBuilderV1(nonce, rfcLocalKeyProvider(), RfcToken.class)
				.checkClaims(new Claim[] {})
				.build();
	}

	private static TokenService<RfcToken> rfcPublicService() {
		return TestContext.builders().publicServiceBuilderV1(rfcPublicKeyProvider(), RfcToken.class)
				.checkClaims(new Claim[] {})
				.build();
	}

	@Test
	public void v1Service_localServiceBuilderRandomNonce() {
		LocalTokenService<Token> service =  TestContext.builders().localServiceBuilderV1(null,
				rfcLocalKeyProvider(), Token.class).build();

		Assert.assertNotNull(service);

		// Simple sign & verify to make sure the builder worked
		Token token = new Token();
		token.setIssuedAt(OffsetDateTime.now().minusMinutes(10));
		token.setExpiration(OffsetDateTime.now().plusMinutes(10));
		String s = service.encode(token);
		Token token2 = service.decode(s);
		Assert.assertEquals(token, token2);
	}

	@Test
	public void v1Service_publicServiceBuilderOverride() {
		PasetoV1.Builder pasetoBuilder = TestContext.builders().pasetoBuilderV1(null);
		PublicTokenService<Token> service =  TestContext.builders().publicServiceBuilderV1(pasetoBuilder,
				rfcPublicKeyProvider(), Token.class).build();

		Assert.assertNotNull(service);

		// Simple sign & verify to make sure the builder worked
		Token token = new Token();
		token.setIssuedAt(OffsetDateTime.now().minusMinutes(10));
		token.setExpiration(OffsetDateTime.now().plusMinutes(10));
		String s = service.encode(token);
		Token token2 = service.decode(s);
		Assert.assertEquals(token, token2);
	}

	// Encryption tests
	@Test
	public void v1Service_rfcVectorE1() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_1;
		encodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	@Test
	public void v1Service_rfcVectorE2() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_2;
		encodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	@Test
	public void v1Service_rfcVectorE3() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_3;
		encodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	@Test
	public void v1Service_rfcVectorE4() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_4;
		encodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	@Test
	public void v1Service_rfcVectorE5() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_5;
		encodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	@Test
	public void v1Service_rfcVectorE6() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_6;
		encodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	// Decryption tests
	@Test
	public void v1Service_rfcVectorE1Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_1;
		decodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	@Test
	public void v1Service_rfcVectorE2Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_2;
		decodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	@Test
	public void v1Service_rfcVectorE3Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_3;
		decodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	@Test
	public void v1Service_rfcVectorE4Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_4;
		decodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	@Test
	public void v1Service_rfcVectorE5Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_5;
		decodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	@Test
	public void v1Service_rfcVectorE6Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_6;
		decodeTestVector(rfcLocalService(tv.getB()), tv);
	}

	// Sign tests
	@Test
	public void v1Service_rfcVectorS1Sign() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_S_1;
		encodeDecodeTestVector(rfcPublicService(), tv);
	}

	@Test
	public void v1Service_rfcVectorS2Sign() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_S_2;
		encodeDecodeTestVector(rfcPublicService(), tv);
	}

	// Verify tests
	@Test
	public void v1Service_rfcVectorS1Verify() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_S_1;
		decodeTestVector(rfcPublicService(), tv);
	}

	@Test
	public void v1Service_rfcVectorS2Verify() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_S_2;
		decodeTestVector(rfcPublicService(), tv);
	}

	// Test defaultValidityPeriod
	@Test
	public void v1Service_local_defaultValidityPeriod() {
		Token token = new Token().setTokenId("id");
		LocalTokenService<Token> service = TestContext.builders().localServiceBuilderV1(null, rfcLocalKeyProvider(),
				Token.class).withDefaultValidityPeriod(Duration.ofMinutes(5)).build();
		String s = service.encode(token);
		Token token2 = service.decode(s);
		Assert.assertNotNull(token2.getIssuedAt());
		Assert.assertNotNull(token2.getExpiration());
	}

	@Test(expected = MissingClaimException.class)
	public void v1Service_local_noExpiry() {
		Token token = new Token().setTokenId("id");
		LocalTokenService<Token> service = TestContext.builders().localServiceBuilderV1(null, rfcLocalKeyProvider(),
				Token.class).build();

		AssertUtils.assertMissingClaimException(() ->
				service.encode(token), "TokenService", token, Token.CLAIM_EXPIRATION);
	}

	@Test
	public void v1Service_public_defaultValidityPeriod() {
		Token token = new Token().setTokenId("id");
		PublicTokenService<Token> service = TestContext.builders().publicServiceBuilderV1(rfcPublicKeyProvider(),
				Token.class).withDefaultValidityPeriod(Duration.ofMinutes(5)).build();
		String s = service.encode(token);
		Token token2 = service.decode(s);
		Assert.assertNotNull(token2.getIssuedAt());
		Assert.assertNotNull(token2.getExpiration());
	}

	@Test(expected = MissingClaimException.class)
	public void v1Service_public_noExpiry() {
		Token token = new Token().setTokenId("id");
		PublicTokenService<Token> service = TestContext.builders().publicServiceBuilderV1(rfcPublicKeyProvider(),
				Token.class).build();

		AssertUtils.assertMissingClaimException(() ->
				service.encode(token), "TokenService", token, Token.CLAIM_EXPIRATION);
	}


	// Constructors / Builder options
	@Test
	public void v1Service_local_ctors1() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(paseto, Token.class, rfcLocalKeyProvider())
				.build();
		checkDefault(service);
	}

	@Test
	public void v1Service_local_ctors2() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(paseto, Token.class, rfcLocalKeyProvider())
				.checkClaims(new Claim[] { new CurrentlyValid() })
				.build();
		checkOnlyCurrentlyValid(service);
	}

	@Test
	public void v1Service_local_ctors3() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(paseto, Token.class, rfcLocalKeyProvider())
				.withDefaultValidityPeriod(Duration.ofMinutes(5))
				.build();
		checkDefaultWithValidity(service);
	}

	@Test
	public void v1Service_local_ctors4() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(paseto, Token.class, rfcLocalKeyProvider())
				.withDefaultValidityPeriod(Duration.ofMinutes(5))
				.checkClaims(new Claim[] { new CurrentlyValid() })
				.build();
		checkOnlyCurrentlyVaildWithValidity(service);
	}

	@Test
	public void v1Service_public_ctors1() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(paseto, Token.class, rfcPublicKeyProvider())
				.build();
		checkDefault(service);
	}

	@Test
	public void v1Service_public_ctors2() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(paseto, Token.class, rfcPublicKeyProvider())
				.checkClaims(new Claim[] { new CurrentlyValid() })
				.build();
		checkOnlyCurrentlyValid(service);
	}

	@Test
	public void v1Service_public_ctors3() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(paseto, Token.class, rfcPublicKeyProvider())
				.withDefaultValidityPeriod(Duration.ofMinutes(5))
				.build();
		checkDefaultWithValidity(service);
	}

	@Test
	public void v1Service_public_ctors4() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(paseto, Token.class, rfcPublicKeyProvider())
				.withDefaultValidityPeriod(Duration.ofMinutes(5))
				.checkClaims(new Claim[] { new CurrentlyValid() })
				.build();
		checkOnlyCurrentlyVaildWithValidity(service);
	}

	private void checkWithoutExpiry(TokenService<Token> service) {
		Token token = new Token().setTokenId("id");
		AssertUtils.assertMissingClaimException(() ->
				service.encode(token), "TokenService", token, Token.CLAIM_EXPIRATION);
	}

	private void checkExpired(TokenService<Token> service) {
		Token token = new Token().setTokenId("id");
		token.setIssuedAt(OffsetDateTime.now().minusMinutes(1));
		token.setExpiration(OffsetDateTime.now().minusSeconds(1));

		service.decode(service.encode(token));
	}

	private void checkIssuedInFuture(TokenService<Token> service) {
		Token token = new Token().setTokenId("id");
		token.setIssuedAt(OffsetDateTime.now().plusMinutes(1));
		token.setExpiration(OffsetDateTime.now().plusMinutes(5));
		service.decode(service.encode(token));
	}

	private void checkDefault(TokenService<Token> service) {
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

	private void checkOnlyCurrentlyValid(TokenService<Token> service) {
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

	private void checkDefaultWithValidity(TokenService<Token> service) {
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

	private void checkOnlyCurrentlyVaildWithValidity(TokenService<Token> service) {
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
