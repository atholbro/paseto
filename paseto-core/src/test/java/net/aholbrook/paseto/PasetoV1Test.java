package net.aholbrook.paseto;

import net.aholbrook.paseto.crypto.TestNonceGenerator;
import net.aholbrook.paseto.crypto.v1.V1CryptoProvider;
import net.aholbrook.paseto.crypto.v1.bc.BouncyCastleV1CryptoProvider;
import net.aholbrook.paseto.data.RfcTestVectors;
import net.aholbrook.paseto.data.RfcToken;
import net.aholbrook.paseto.data.TestVector;
import net.aholbrook.paseto.data.TokenTestVectors;
import net.aholbrook.paseto.exception.InvalidFooterException;
import net.aholbrook.paseto.exception.InvalidHeaderException;
import net.aholbrook.paseto.exception.PasetoParseException;
import net.aholbrook.paseto.exception.PasetoStringException;
import net.aholbrook.paseto.exception.SignatureVerificationException;
import net.aholbrook.paseto.keys.KeyPair;
import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.utils.AssertUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@DisplayName("Paseto V1 Test Vectors")
public class PasetoV1Test extends PasetoTest {
	// RFC test vectors
	// Encryption tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Encrypt RFC Vector E1")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE1(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_1);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Encrypt RFC Vector E2")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE2(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Encrypt RFC Vector E3")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE3(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_3);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Encrypt RFC Vector E4")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE4(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_4);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Encrypt RFC Vector E5")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE5(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_5);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Encrypt RFC Vector E6")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE6(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_6);
	}

	// Decryption tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Decrypt RFC Vector E1")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE1Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_1);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Decrypt RFC Vector E2")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE2Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Decrypt RFC Vector E3")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE3Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_3);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Decrypt RFC Vector E4")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE4Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_4);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Decrypt RFC Vector E5")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE5Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_5);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Decrypt RFC Vector E6")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorE6Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_E_6);
	}

	// Sign tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Sign RFC Vector S1")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorS1Sign(Paseto.Builder builder) {
		signTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_S_1, false);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Sign RFC Vector S2")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorS2Sign(Paseto.Builder builder) {
		signTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_S_2, false);
	}

	// Verify tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Verify RFC Vector S1")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorS1Verify(Paseto.Builder builder) {
		verifyTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_S_1);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@DisplayName("Sign RFC Vector S2")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_RfcVectorS2Verify(Paseto.Builder builder) {
		verifyTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V1_S_2);
	}

	// Other test vectors
	// Encryption tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1Local(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_1_V1_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1LocalWithFooter(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1LocalWithStringFooter(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_1_V1_LOCAL_WITH_STRING_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token2Local(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_2_V1_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token2LocalWithFooter(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_2_V1_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token3Local(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_3_V1_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token3LocalWithFooter(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_3_V1_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token4Local(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_4_V1_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token4LocalWithFooter(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_4_V1_LOCAL_WITH_FOOTER);
	}

	// Decryption tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1LocalDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_1_V1_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1LocalWithFooterDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1LocalWithStringFooterDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_1_V1_LOCAL_WITH_STRING_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token2LocalDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_2_V1_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token2LocalWithFooterDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_2_V1_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token3LocalDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_3_V1_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token3LocalWithFooterDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_3_V1_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token4LocalDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_4_V1_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token4LocalWithFooterDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_4_V1_LOCAL_WITH_FOOTER);
	}

	// Sign tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1Public(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_1_V1_PUBLIC, false);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1PublicWithFooter(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER, false);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1PublicWithStringFooter(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_1_V1_PUBLIC_WITH_STRING_FOOTER, false);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token2Public(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_2_V1_PUBLIC, false);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token2PublicWithFooter(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_2_V1_PUBLIC_WITH_FOOTER, false);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token3Public(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_3_V1_PUBLIC, false);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token3PublicWithFooter(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_3_V1_PUBLIC_WITH_FOOTER, false);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token4Public(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_4_V1_PUBLIC, false);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token4PublicWithFooter(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_4_V1_PUBLIC_WITH_FOOTER, false);
	}

	// Verify tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1PublicVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_1_V1_PUBLIC);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1PublicWithFooterVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1PublicWithStringFooterVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_1_V1_PUBLIC_WITH_STRING_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token2PublicVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_2_V1_PUBLIC);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token2PublicWithFooterVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_2_V1_PUBLIC_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token3PublicVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_3_V1_PUBLIC);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token3PublicWithFooterVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_3_V1_PUBLIC_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token4PublicVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_4_V1_PUBLIC);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token4PublicWithFooterVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_4_V1_PUBLIC_WITH_FOOTER);
	}

	// Footer extraction tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_extractFooter(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto paseto = builder.build();

		KeyId footer = paseto.extractFooter(tv.getToken(), KeyId.class);
		Assertions.assertEquals(tv.getFooter(), footer, "extracted footer != footer");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_extractFooterString(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto paseto = builder.build();

		String footerString = paseto.extractFooter(tv.getToken());
		KeyId footer = builder.encodingProvider.decode(footerString, KeyId.class);
		Assertions.assertEquals(tv.getFooter(), footer, "extracted footer != footer");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_extractMissingFooter(Paseto.Builder builder) {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_PUBLIC;
		Paseto paseto = builder.build();

		KeyId footer = paseto.extractFooter(tv.getToken(), KeyId.class);
		Assertions.assertNull(footer, "footer not null");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_localDecryptWithFooter(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

		TokenWithFooter<Token, KeyId> result = paseto.decryptWithFooter(tv.getToken(), tv.getLocalKey(), tv.getPayloadClass(),
				KeyId.class);
		Assertions.assertEquals(tv.getFooter(), result.getFooter(), "extracted footer != footer");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_localDecryptWithFooterString(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

		TokenWithFooter<Token, String> result = paseto.decryptWithFooter(tv.getToken(), tv.getLocalKey(), tv.getPayloadClass());
		KeyId footer = builder.encodingProvider.decode(result.getFooter(), KeyId.class);
		Assertions.assertEquals(tv.getFooter(), footer, "extracted footer != footer");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_publicVerifyWithFooter(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

		TokenWithFooter<Token, KeyId> result = paseto.verifyWithFooter(tv.getToken(), tv.getPublicKey(), tv.getPayloadClass(),
				KeyId.class);
		Assertions.assertEquals(tv.getFooter(), result.getFooter(), "extracted footer != footer");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_publicVerifyWithFooterString(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

		TokenWithFooter<Token, String> result = paseto.verifyWithFooter(tv.getToken(), tv.getPublicKey(), tv.getPayloadClass());
		KeyId footer = builder.encodingProvider.decode(result.getFooter(), KeyId.class);
		Assertions.assertEquals(tv.getFooter(), footer, "extracted footer != footer");
	}

	// Modification / tampering tests
	// Modify the token contents after encryption, then try to decrypt, should produce a SignatureVerificationException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_modifyPayload(Paseto.Builder builder) {
		Assertions.assertThrows(SignatureVerificationException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

			// encrypt and modify
			String token = paseto.encrypt(tv.getPayload(), tv.getLocalKey());
			token = modify(token, new int[]{20, 15, 20});

			// attempt to decrypt
			paseto.decrypt(token, tv.getLocalKey(), tv.getPayloadClass());
		});
	}

	// Modify the token footer after encryption, then try to decrypt, should produce a SignatureVerificationException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_modifyFooter(Paseto.Builder builder) {
		Assertions.assertThrows(SignatureVerificationException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

			// encrypt and modify
			String token = paseto.encrypt(tv.getPayload(), tv.getLocalKey());
			token = modify(token, new int[]{token.length() - 1, token.length() - 4, token.length() - 6});

			// attempt to decrypt
			paseto.decrypt(token, tv.getLocalKey(), tv.getPayloadClass());
		});
	}

	// Decrypt with a different key, should fail with a SignatureVerificationException
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_decryptWrongKey(Paseto.Builder builder) {
		Assertions.assertThrows(SignatureVerificationException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

			// attempt to decrypt
			paseto.decrypt(tv.getToken(), RfcTestVectors.RFC_TEST_V1_KEY, tv.getPayloadClass());
		});
	}

	// Verify with a different public key, should fail with a SignatureVerificationException
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_verifyWrongKey(Paseto.Builder builder) {
		Assertions.assertThrows(SignatureVerificationException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_PUBLIC;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

			// attempt to decrypt
			paseto.verify(tv.getToken(), RfcTestVectors.RFC_TEST_V1_PK, tv.getPayloadClass());
		});
	}

	// Attempt to decrypt A V2 local token as a V1 local token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_v2LocalAsV1Local(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;

			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.decrypt(tv.getToken(), TokenTestVectors.TEST_V1_KEY, tv.getPayloadClass());
		});
	}

	// Attempt to decrypt A V2 local token as a V1 public token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_v2LocalAsV1Public(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;

			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.verify(tv.getToken(), TokenTestVectors.TEST_V1_PK, tv.getPayloadClass());
		});
	}

	// Attempt to decrypt A V2 public token with a V1 local token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_v2PublicAsV1Local(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;

			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.decrypt(tv.getToken(), TokenTestVectors.TEST_V1_KEY, tv.getPayloadClass());
		});
	}

	// Attempt to decrypt A V2 public token with a V1 public token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_v2PublicAsV1Public(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;

			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.verify(tv.getToken(), TokenTestVectors.TEST_V1_PK, tv.getPayloadClass());
		});
	}

	// Attempt to verify A V1 local token as a V1 public token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_publicAsLocal(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;

			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.decrypt(tv.getToken(), TokenTestVectors.TEST_V1_KEY, tv.getPayloadClass());
		});
	}

	// Attempt to verify A V1 public token as a V1 local token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_localAsPublic(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;

			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.verify(tv.getToken(), TokenTestVectors.TEST_V1_PK, tv.getPayloadClass());
		});
	}

	// Attempt to verify local token with a missing footer, should fail with a InvalidFooterException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_localMissingFooter(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidFooterException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;

			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.decrypt(tv.getToken(), tv.getLocalKey(), "not-the-footer", tv.getPayloadClass());
		});
	}

	// Attempt to verify public token with a missing footer, should fail with a InvalidFooterException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_publicMissingFooter(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidFooterException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_PUBLIC;

			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.verify(tv.getToken(), tv.getPublicKey(), "not-the-footer", tv.getPayloadClass());
		});
	}

	// Attempt to verify local token with an incorrect footer, should fail with a InvalidFooterException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_localWrongFooter(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidFooterException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;

			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.decrypt(tv.getToken(), tv.getLocalKey(), "not-the-footer", tv.getPayloadClass());
		});
	}

	// Attempt to verify public token with an incorrect footer, should fail with a InvalidFooterException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_publicWrongFooter(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidFooterException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;

			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.verify(tv.getToken(), tv.getPublicKey(), "not-the-footer", tv.getPayloadClass());
		});
	}

	// Errors
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_badInput(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoStringException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.decrypt("junk", tv.getLocalKey(), tv.getPayloadClass());
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_badTokenDecrypt(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoStringException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.decrypt("v1.local.", tv.getLocalKey(), tv.getPayloadClass());
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_badTokenVerify(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoStringException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_PUBLIC;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.verify("v1.local.", tv.getPublicKey(), tv.getPayloadClass());
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_shortTokenLocal(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoStringException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.decrypt("v1.local.c29tZXRoaW5n", tv.getLocalKey(), tv.getPayloadClass());
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_shortTokenPublic(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoStringException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_PUBLIC;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			paseto.verify("v1.public.c29tZXRoaW5n", tv.getPublicKey(), tv.getPayloadClass());
		});
	}

	// Nonce tests
	// Generates a V1 Local token twice, the results should be different due to nonce rng.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_localNonce(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		Paseto paseto = builder.build();
		String token1 = paseto.encrypt(tv.getPayload(), tv.getLocalKey(), tv.getFooter());
		String token2 = paseto.encrypt(tv.getPayload(), tv.getLocalKey(), tv.getFooter());
		Assertions.assertNotEquals(token1, token2, "nonce failed, 2 tokens have same contents");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_publicNonce(Paseto.Builder builder) { // TODO naming, nonce not used but results should still differ
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto paseto = builder.build();
		String token1 = paseto.sign(tv.getPayload(), tv.getSecretKey(), tv.getFooter());
		String token2 = paseto.sign(tv.getPayload(), tv.getSecretKey(), tv.getFooter());
		Assertions.assertNotEquals(token1, token2, "nonce failed, 2 tokens have same contents");
	}

	// Key pair generation tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_token1_generateKeyPair(Paseto.Builder builder) {
		Paseto paseto = builder.build();
		KeyPair keyPair = paseto.generateKeyPair();

		// encrypt with new key
		String token = paseto.sign(TokenTestVectors.TOKEN_1, keyPair.getSecretKey());
		// now decrypt, should work
		Token payload = paseto.verify(token, keyPair.getPublicKey(), Token.class);
		Assertions.assertEquals(TokenTestVectors.TOKEN_1, payload, "decrypted payload != original payload");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_local_parseException_missingSections(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoParseException.class, () -> {
			Paseto paseto = builder.build();

			AssertUtils.assertPasetoParseException(() ->
							paseto.decrypt("", RfcTestVectors.RFC_TEST_V1_KEY, RfcToken.class),
					"", PasetoParseException.Reason.MISSING_SECTIONS, 0);
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_public_parseException_missingSections(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoParseException.class, () -> {
			Paseto paseto = builder.build();

			AssertUtils.assertPasetoParseException(() ->
							paseto.verify("", RfcTestVectors.RFC_TEST_V1_PK, RfcToken.class),
					"", PasetoParseException.Reason.MISSING_SECTIONS, 0);
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_local_parseException_payloadLength(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoParseException.class, () -> {
			Paseto paseto = builder.build();

			AssertUtils.assertPasetoParseException(() ->
							paseto.decrypt("v1.local.aa", RfcTestVectors.RFC_TEST_V1_KEY, RfcToken.class),
					"v1.local.aa", PasetoParseException.Reason.PAYLOAD_LENGTH, 81);
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV1Builders")
	public void v1_public_parseException_payloadLength(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoParseException.class, () -> {
			Paseto paseto = builder.build();

			AssertUtils.assertPasetoParseException(() ->
							paseto.verify("v1.public.aa", RfcTestVectors.RFC_TEST_V1_PK, RfcToken.class),
					"v1.public.aa", PasetoParseException.Reason.PAYLOAD_LENGTH, 257);
		});
	}

	@Test
	@DisplayName("V1 Builder has a default crypto provider.")
	public void v1_builder_withDefaultV1CryptoProvider() {
		PasetoV1.Builder builder = new PasetoV1.Builder();
		builder.build();
		Assertions.assertNotNull(builder.v1CryptoProvider);
	}

	@Test
	@DisplayName("V1 Builder can override crypto provider.")
	public void v1_builder_withV1CryptoProvider() {
		V1CryptoProvider provider = new BouncyCastleV1CryptoProvider();
		PasetoV1.Builder builder = new PasetoV1.Builder();
		builder.withV1CryptoProvider(provider);
		Assertions.assertEquals(provider, builder.v1CryptoProvider);
	}
}
