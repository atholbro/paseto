package net.aholbrook.paseto;

import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.CurrentlyValid;
import net.aholbrook.paseto.data.RfcTestVectors;
import net.aholbrook.paseto.data.RfcToken;
import net.aholbrook.paseto.data.TestVector;
import net.aholbrook.paseto.data.TokenTestVectors;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.keys.AsymmetricPublicKey;
import net.aholbrook.paseto.keys.AsymmetricSecretKey;
import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.utils.AssertUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.OffsetDateTime;

public class PasetoV1ServiceTest extends PasetoServiceTest {
	@Override
	protected LocalTokenService.KeyProvider rfcLocalKeyProvider() {
		return () -> RfcTestVectors.RFC_TEST_V1_KEY;
	}

	@Override
	protected PublicTokenService.KeyProvider rfcPublicKeyProvider() {
		return new PublicTokenService.KeyProvider() {
			@Override
			public AsymmetricSecretKey getSecretKey() {
				return RfcTestVectors.RFC_TEST_V1_SK;
			}

			@Override
			public AsymmetricPublicKey getPublicKey() {
				return RfcTestVectors.RFC_TEST_V1_PK;
			}
		};
	}

	@Override
	protected LocalTokenService.KeyProvider tokenLocalKeyProvider() {
		return () -> TokenTestVectors.TEST_V1_KEY;
	}

	@Override
	protected PublicTokenService.KeyProvider tokenPublicKeyProvider() {
		return new PublicTokenService.KeyProvider() {
			@Override
			public AsymmetricSecretKey getSecretKey() {
				return TokenTestVectors.TEST_V1_SK;
			}

			@Override
			public AsymmetricPublicKey getPublicKey() {
				return TokenTestVectors.TEST_V1_PK;
			}
		};
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_localServiceBuilderRandomNonce(Paseto.Builder builder) {
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(Token.class, rfcLocalKeyProvider())
				.withPaseto(builder.build())
				.build();

		Assertions.assertNotNull(service);

		// Simple sign & verify to make sure the builder worked
		Token token = new Token();
		token.setIssuedAt(OffsetDateTime.now().minusMinutes(10).toEpochSecond());
		token.setExpiration(OffsetDateTime.now().plusMinutes(10).toEpochSecond());
		String s = service.encode(token);
		Token token2 = service.decode(s);
		Assertions.assertEquals(token, token2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_publicServiceBuilderOverride(Paseto.Builder builder) {
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(Token.class, rfcPublicKeyProvider())
				.withPaseto(builder.build())
				.build();

		Assertions.assertNotNull(service);

		// Simple sign & verify to make sure the builder worked
		Token token = new Token();
		token.setIssuedAt(OffsetDateTime.now().minusMinutes(10).toEpochSecond());
		token.setExpiration(OffsetDateTime.now().plusMinutes(10).toEpochSecond());
		String s = service.encode(token);
		Token token2 = service.decode(s);
		Assertions.assertEquals(token, token2);
	}

	// Encryption tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE1(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_1;
		encodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE2(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_2;
		encodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE3(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_3;
		encodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE4(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_4;
		encodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE5(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_5;
		encodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE6(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_6;
		encodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	// Decryption tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE1Decrypt(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_1;
		decodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE2Decrypt(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_2;
		decodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE3Decrypt(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_3;
		decodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE4Decrypt(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_4;
		decodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE5Decrypt(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_5;
		decodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorE6Decrypt(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_E_6;
		decodeTestVector(rfcLocalService(builder, tv.getNonce()), tv);
	}

	// Sign tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorS1Sign(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_S_1;
		encodeDecodeTestVector(rfcPublicService(builder), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorS2Sign(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_S_2;
		encodeDecodeTestVector(rfcPublicService(builder), tv);
	}

	// Verify tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorS1Verify(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_S_1;
		decodeTestVector(rfcPublicService(builder), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_rfcVectorS2Verify(Paseto.Builder builder) {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V1_S_2;
		decodeTestVector(rfcPublicService(builder), tv);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_local_decodeWithFooter(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		TokenService<Token> service = tokenLocalService(builder, tv.getNonce());

		TokenWithFooter<Token, KeyId> result = service.decodeWithFooter(tv.getToken(), KeyId.class);
		Assertions.assertEquals(tv.getPayload(), result.getToken());
		Assertions.assertEquals(tv.getFooter(), result.getFooter());
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_public_decodeWithFooter(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		TokenService<Token> service = tokenPublicService(builder);

		TokenWithFooter<Token, KeyId> result = service.decodeWithFooter(tv.getToken(), KeyId.class);
		Assertions.assertEquals(tv.getPayload(), result.getToken());
		Assertions.assertEquals(tv.getFooter(), result.getFooter());
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_local_extractFooter(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		TokenService<Token> service = tokenLocalService(builder, tv.getNonce());

		KeyId result = service.getFooter(tv.getToken(), KeyId.class);
		Assertions.assertEquals(tv.getFooter(), result);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_public_extractFooter(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		TokenService<Token> service = tokenPublicService(builder);

		KeyId result = service.getFooter(tv.getToken(), KeyId.class);
		Assertions.assertEquals(tv.getFooter(), result);
	}

	// Test defaultValidityPeriod
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_local_defaultValidityPeriod(Paseto.Builder builder) {
		Token token = new Token().setTokenId("id");
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(Token.class, rfcLocalKeyProvider())
				.withDefaultValidityPeriod(5L * 60L)
				.withPaseto(builder.build())
				.build();

		String s = service.encode(token);
		Token token2 = service.decode(s);
		Assertions.assertNotNull(token2.getIssuedAt());
		Assertions.assertNotNull(token2.getExpiration());
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_local_noExpiry(Paseto.Builder builder) {
		Assertions.assertThrows(MissingClaimException.class, () -> {
			Token token = new Token().setTokenId("id");
			LocalTokenService<Token> service = new LocalTokenService.Builder<>(Token.class, rfcLocalKeyProvider())
					.withPaseto(builder.build())
					.build();

			AssertUtils.assertMissingClaimException(() ->
					service.encode(token), "TokenService", token, Token.CLAIM_EXPIRATION);
		});

	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_public_defaultValidityPeriod(Paseto.Builder builder) {
		Token token = new Token().setTokenId("id");
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(Token.class, rfcPublicKeyProvider())
				.withDefaultValidityPeriod(5L * 60L)
				.withPaseto(builder.build())
				.build();

		String s = service.encode(token);
		Token token2 = service.decode(s);
		Assertions.assertNotNull(token2.getIssuedAt());
		Assertions.assertNotNull(token2.getExpiration());
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_public_noExpiry(Paseto.Builder builder) {
		Assertions.assertThrows(MissingClaimException.class, () -> {
			Token token = new Token().setTokenId("id");
			PublicTokenService<Token> service = new PublicTokenService.Builder<>(Token.class, rfcPublicKeyProvider())
					.withPaseto(builder.build())
					.build();

			AssertUtils.assertMissingClaimException(() ->
					service.encode(token), "TokenService", token, Token.CLAIM_EXPIRATION);
		});
	}


	// Constructors / Builder options
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_local_ctors1(Paseto.Builder builder) {
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(Token.class, rfcLocalKeyProvider())
				.withPaseto(builder.build())
				.build();
		checkDefault(service);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_local_ctors2(Paseto.Builder builder) {
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(Token.class, rfcLocalKeyProvider())
				.withPaseto(builder.build())
				.checkClaims(new Claim[] {new CurrentlyValid()})
				.build();
		checkOnlyCurrentlyValid(service);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_local_ctors3(Paseto.Builder builder) {
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(Token.class, rfcLocalKeyProvider())
				.withPaseto(builder.build())
				.withDefaultValidityPeriod(5L * 60L)
				.build();
		checkDefaultWithValidity(service);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_local_ctors4(Paseto.Builder builder) {
		LocalTokenService<Token> service = new LocalTokenService.Builder<>(Token.class, rfcLocalKeyProvider())
				.withPaseto(builder.build())
				.withDefaultValidityPeriod(5L * 60L)
				.checkClaims(new Claim[] {new CurrentlyValid()})
				.build();
		checkOnlyCurrentlyValidWithValidity(service);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_public_ctors1(Paseto.Builder builder) {
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(Token.class, rfcPublicKeyProvider())
				.withPaseto(builder.build())
				.build();
		checkDefault(service);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_public_ctors2(Paseto.Builder builder) {
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(Token.class, rfcPublicKeyProvider())
				.withPaseto(builder.build())
				.checkClaims(new Claim[] {new CurrentlyValid()})
				.build();
		checkOnlyCurrentlyValid(service);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_public_ctors3(Paseto.Builder builder) {
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(Token.class, rfcPublicKeyProvider())
				.withPaseto(builder.build())
				.withDefaultValidityPeriod(5L * 60L)
				.build();
		checkDefaultWithValidity(service);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1Service_public_ctors4(Paseto.Builder builder) {
		PublicTokenService<Token> service = new PublicTokenService.Builder<>(Token.class, rfcPublicKeyProvider())
				.withPaseto(builder.build())
				.withDefaultValidityPeriod(5L * 60L)
				.checkClaims(new Claim[] {new CurrentlyValid()})
				.build();
		checkOnlyCurrentlyValidWithValidity(service);
	}

	@Test
	public void v1Service_local_builder_withV1() {
		Assertions.assertNotNull(new LocalTokenService.Builder<>(Token.class,
				tokenLocalKeyProvider()).withV1().build());
	}

	@Test
	public void v1Service_public_builder_withV1() {
		Assertions.assertNotNull(new PublicTokenService.Builder<>(Token.class,
				tokenPublicKeyProvider()).withV1().build());
	}
}
