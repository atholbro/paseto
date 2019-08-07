package net.aholbrook.paseto.test.common;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.PasetoV1;
import net.aholbrook.paseto.TokenWithFooter;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.CurrentlyValid;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.test.common.data.RfcTestVectors;
import net.aholbrook.paseto.test.common.data.RfcToken;
import net.aholbrook.paseto.test.common.data.TestVector;
import net.aholbrook.paseto.test.common.data.TokenTestVectors;
import net.aholbrook.paseto.test.common.utils.AssertUtils;
import net.aholbrook.paseto.test.common.utils.TestContext;
import net.aholbrook.paseto.time.OffsetDateTime;
import org.junit.Assert;
import org.junit.Test;

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

	private static LocalTokenService.KeyProvider tokenLocalKeyProvider() {
		return () -> TokenTestVectors.TEST_KEY;
	}

	private static PublicTokenService.KeyProvider tokenPublicKeyProvider() {
		return new PublicTokenService.KeyProvider() {
			@Override
			public byte[] getSecretKey() {
				return TokenTestVectors.TEST_RSA_PRIVATE_KEY;
			}

			@Override
			public byte[] getPublicKey() {
				return TokenTestVectors.TEST_RSA_PUBLIC_KEY;
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

	private static TokenService<Token> tokenLocalService(byte[] nonce) {
		return TestContext.builders().localServiceBuilderV1(nonce, tokenLocalKeyProvider(), Token.class)
				.checkClaims(new Claim[] {})
				.build();
	}

	private static TokenService<Token> tokenPublicService() {
		return TestContext.builders().publicServiceBuilderV1(tokenPublicKeyProvider(), Token.class)
				.checkClaims(new Claim[] {})
				.build();
	}

	@Test
	public void v1Service_localServiceBuilderRandomNonce() {
		LocalTokenService<Token> service = TestContext.builders().localServiceBuilderV1(null,
				rfcLocalKeyProvider(), Token.class).build();

		Assert.assertNotNull(service);

		// Simple sign & verify to make sure the builder worked
		Token token = new Token();
		token.setIssuedAt(OffsetDateTime.now().minusMinutes(10).toEpochSecond());
		token.setExpiration(OffsetDateTime.now().plusMinutes(10).toEpochSecond());
		String s = service.encode(token);
		Token token2 = service.decode(s);
		Assert.assertEquals(token, token2);
	}

	@Test
	public void v1Service_publicServiceBuilderOverride() {
		PasetoV1.Builder pasetoBuilder = TestContext.builders().pasetoBuilderV1(null);
		PublicTokenService<Token> service = TestContext.builders().publicServiceBuilderV1(pasetoBuilder,
				rfcPublicKeyProvider(), Token.class).build();

		Assert.assertNotNull(service);

		// Simple sign & verify to make sure the builder worked
		Token token = new Token();
		token.setIssuedAt(OffsetDateTime.now().minusMinutes(10).toEpochSecond());
		token.setExpiration(OffsetDateTime.now().plusMinutes(10).toEpochSecond());
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

	@Test
	public void v1Service_local_decodeWithFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		TokenService<Token> service = tokenLocalService(tv.getB());

		TokenWithFooter<Token, KeyId> result = service.decodeWithFooter(tv.getToken(), KeyId.class);
		Assert.assertEquals(tv.getPayload(), result.getToken());
		Assert.assertEquals(tv.getFooter(), result.getFooter());
	}

	@Test
	public void v1Service_public_decodeWithFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		TokenService<Token> service = tokenPublicService();

		TokenWithFooter<Token, KeyId> result = service.decodeWithFooter(tv.getToken(), KeyId.class);
		Assert.assertEquals(tv.getPayload(), result.getToken());
		Assert.assertEquals(tv.getFooter(), result.getFooter());
	}

	@Test
	public void v1Service_local_extractFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		TokenService<Token> service = tokenLocalService(tv.getB());

		KeyId result = service.getFooter(tv.getToken(), KeyId.class);
		Assert.assertEquals(tv.getFooter(), result);
	}

	@Test
	public void v1Service_public_extractFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		TokenService<Token> service = tokenPublicService();

		KeyId result = service.getFooter(tv.getToken(), KeyId.class);
		Assert.assertEquals(tv.getFooter(), result);
	}

	// Test defaultValidityPeriod
	@Test
	public void v1Service_local_defaultValidityPeriod() {
		Token token = new Token().setTokenId("id");
		LocalTokenService<Token> service = TestContext.builders().localServiceBuilderV1(null, rfcLocalKeyProvider(),
				Token.class).withDefaultValidityPeriod(5L * 60L).build();
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
				Token.class).withDefaultValidityPeriod(5L * 60L).build();
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
				.checkClaims(new Claim[] {new CurrentlyValid()})
				.build();
		checkOnlyCurrentlyValid(service);
	}

	@Test
	public void v1Service_local_ctors3() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(paseto, Token.class, rfcLocalKeyProvider())
				.withDefaultValidityPeriod(5L * 60L)
				.build();
		checkDefaultWithValidity(service);
	}

	@Test
	public void v1Service_local_ctors4() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(paseto, Token.class, rfcLocalKeyProvider())
				.withDefaultValidityPeriod(5L * 60L)
				.checkClaims(new Claim[] {new CurrentlyValid()})
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
				.checkClaims(new Claim[] {new CurrentlyValid()})
				.build();
		checkOnlyCurrentlyValid(service);
	}

	@Test
	public void v1Service_public_ctors3() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(paseto, Token.class, rfcPublicKeyProvider())
				.withDefaultValidityPeriod(5L * 60L)
				.build();
		checkDefaultWithValidity(service);
	}

	@Test
	public void v1Service_public_ctors4() {
		Paseto paseto = TestContext.builders().pasetoBuilderV1(null).build();
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(paseto, Token.class, rfcPublicKeyProvider())
				.withDefaultValidityPeriod(5L * 60L)
				.checkClaims(new Claim[] {new CurrentlyValid()})
				.build();
		checkOnlyCurrentlyVaildWithValidity(service);
	}
}
