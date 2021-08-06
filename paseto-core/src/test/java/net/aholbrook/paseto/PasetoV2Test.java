package net.aholbrook.paseto;

import net.aholbrook.paseto.base64.jvm8.Base64Provider;
import net.aholbrook.paseto.base64.jvm8.jvm8.Jvm8Base64Provider;
import net.aholbrook.paseto.keys.KeyPair;
import net.aholbrook.paseto.crypto.TestNonceGenerator;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;
import net.aholbrook.paseto.crypto.v2.bc.BouncyCastleV2CryptoProvider;
import net.aholbrook.paseto.data.CustomToken;
import net.aholbrook.paseto.data.RfcTestVectors;
import net.aholbrook.paseto.data.RfcToken;
import net.aholbrook.paseto.data.TestVector;
import net.aholbrook.paseto.data.TokenTestVectors;
import net.aholbrook.paseto.exception.DecryptionException;
import net.aholbrook.paseto.exception.InvalidFooterException;
import net.aholbrook.paseto.exception.InvalidHeaderException;
import net.aholbrook.paseto.exception.PasetoParseException;
import net.aholbrook.paseto.exception.PasetoStringException;
import net.aholbrook.paseto.exception.SignatureVerificationException;
import net.aholbrook.paseto.keys.AsymmetricPublicKey;
import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.utils.AssertUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class PasetoV2Test extends PasetoTest {
	// RFC test vectors
	// Encryption tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE1(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_1);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE2(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE3(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_3);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE4(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_4);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE5(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_5);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE6(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_6);
	}

	// Decryption tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE1Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_1);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE2Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE3Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_3);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE4Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_4);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE5Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_5);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorE6Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_E_6);
	}

	// Sign tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorS1Sign(Paseto.Builder builder) {
		signTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_S_1, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorS2Sign(Paseto.Builder builder) {
		signTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_S_2, true);
	}

	// Verify tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorS1Verify(Paseto.Builder builder) {
		verifyTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_S_1);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_RfcVectorS2Verify(Paseto.Builder builder) {
		verifyTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V2_S_2);
	}

	// Other test vectors
	// Encryption tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1Local(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_1_V2_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1LocalWithFooter(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1LocalWithStringFooter(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_1_V2_LOCAL_WITH_STRING_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token2Local(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_2_V2_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token2LocalWithFooter(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_2_V2_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token3Local(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_3_V2_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token3LocalWithFooter(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_3_V2_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token4Local(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_4_V2_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token4LocalWithFooter(Paseto.Builder builder) {
		encryptTestVector(builder, TokenTestVectors.TV_4_V2_LOCAL_WITH_FOOTER);
	}

	// Decryption tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1LocalDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_1_V2_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1LocalWithFooterDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1LocalWithStringFooterDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_1_V2_LOCAL_WITH_STRING_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token2LocalDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_2_V2_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token2LocalWithFooterDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_2_V2_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token3LocalDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_3_V2_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token3LocalWithFooterDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_3_V2_LOCAL_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token4LocalDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_4_V2_LOCAL);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token4LocalWithFooterDecrypt(Paseto.Builder builder) {
		decryptTestVector(builder, TokenTestVectors.TV_4_V2_LOCAL_WITH_FOOTER);
	}

	// Sign tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1Public(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_1_V2_PUBLIC, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1PublicWithFooter(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1PublicWithStringFooter(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_1_V2_PUBLIC_WITH_STRING_FOOTER, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token2Public(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_2_V2_PUBLIC, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token2PublicWithFooter(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_2_V2_PUBLIC_WITH_FOOTER, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token3Public(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_3_V2_PUBLIC, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token3PublicWithFooter(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_3_V2_PUBLIC_WITH_FOOTER, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token4Public(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_4_V2_PUBLIC, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token4PublicWithFooter(Paseto.Builder builder) {
		signTestVector(builder, TokenTestVectors.TV_4_V2_PUBLIC_WITH_FOOTER, true);
	}

	// Verify tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1PublicVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_1_V2_PUBLIC);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1PublicWithFooterVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1PublicWithStringFooterVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_1_V2_PUBLIC_WITH_STRING_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token2PublicVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_2_V2_PUBLIC);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token2PublicWithFooterVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_2_V2_PUBLIC_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token3PublicVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_3_V2_PUBLIC);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token3PublicWithFooterVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_3_V2_PUBLIC_WITH_FOOTER);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token4PublicVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_4_V2_PUBLIC);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token4PublicWithFooterVerify(Paseto.Builder builder) {
		verifyTestVector(builder, TokenTestVectors.TV_4_V2_PUBLIC_WITH_FOOTER);
	}

	// Footer extraction tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_extractFooter(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = builder.build();

		KeyId footer = paseto.extractFooter(tv.getToken(), KeyId.class);
		Assertions.assertEquals(tv.getFooter(), footer, "extracted footer != footer");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_extractFooterString(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = builder.build();

		String footerString = paseto.extractFooter(tv.getToken());
		KeyId footer = builder.encodingProvider.decode(footerString, KeyId.class);
		Assertions.assertEquals(tv.getFooter(), footer, "extracted footer != footer");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_extractMissingFooter(Paseto.Builder builder) {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_PUBLIC;
		Paseto paseto = builder.build();

		KeyId footer = paseto.extractFooter(tv.getToken(), KeyId.class);
		Assertions.assertNull(footer, "footer not null");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_localDecryptWithFooter(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;
		Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

		TokenWithFooter<Token, KeyId> result = paseto.decryptWithFooter(tv.getToken(), tv.getLocalKey(), tv.getPayloadClass(),
				KeyId.class);
		Assertions.assertEquals(tv.getFooter(), result.getFooter(), "extracted footer != footer");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_localDecryptWithFooterString(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;
		Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

		TokenWithFooter<Token, String> result = paseto.decryptWithFooter(tv.getToken(), tv.getLocalKey(), tv.getPayloadClass());
		KeyId footer = builder.encodingProvider.decode(result.getFooter(), KeyId.class);
		Assertions.assertEquals(tv.getFooter(), footer, "extracted footer != footer");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v1_token1_publicVerifyWithFooter(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

		TokenWithFooter<Token, KeyId> result = paseto.verifyWithFooter(tv.getToken(), tv.getPublicKey(), tv.getPayloadClass(),
				KeyId.class);
		Assertions.assertEquals(tv.getFooter(), result.getFooter(), "extracted footer != footer");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_publicVerifyWithFooterString(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

		TokenWithFooter<Token, String> result = paseto.verifyWithFooter(tv.getToken(), tv.getPublicKey(), tv.getPayloadClass());
		KeyId footer = builder.encodingProvider.decode(result.getFooter(), KeyId.class);
		Assertions.assertEquals(tv.getFooter(), footer, "extracted footer != footer");
	}

	// Modification / tampering tests
	// Modify the token contents after encryption, then try to decrypt, should produce a DecryptionException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_modifyPayload(Paseto.Builder builder) {
		Assertions.assertThrows(DecryptionException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

			// encrypt and modify
			String token = paseto.encrypt(tv.getPayload(), tv.getLocalKey());
			token = modify(token, new int[]{20, 15, 20});

			// attempt to decrypt
			paseto.decrypt(token, tv.getLocalKey(), tv.getPayloadClass());
		});
	}

	// Modify the token footer after encryption, then try to decrypt, should produce a DecryptionException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_modifyFooter(Paseto.Builder builder) {
		Assertions.assertThrows(DecryptionException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

			// encrypt and modify
			String token = paseto.encrypt(tv.getPayload(), tv.getLocalKey());
			token = modify(token, new int[]{token.length() - 1, token.length() - 4, token.length() - 6});

			// attempt to decrypt
			paseto.decrypt(token, tv.getLocalKey(), tv.getPayloadClass());
		});
	}

	// Decrypt with a different key, should fail with a DecryptionException
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_decryptWrongKey(Paseto.Builder builder) {
		Assertions.assertThrows(DecryptionException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

			// attempt to decrypt
			paseto.decrypt(tv.getToken(), RfcTestVectors.RFC_TEST_V2_KEY, tv.getPayloadClass());
		});
	}

	// Verify with a different public key, should fail with a SignatureVerificationException
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_verifyWrongKey(Paseto.Builder builder) {
		Assertions.assertThrows(SignatureVerificationException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_PUBLIC;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();

			// attempt to decrypt
			paseto.verify(tv.getToken(), new AsymmetricPublicKey(RfcTestVectors.RFC_TEST_PK, Version.V2),
					tv.getPayloadClass());
		});
	}

	// Attempt to decrypt A V1 local token with as V2 local token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_v1LocalAsV2Local(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertInvalidHeaderException(() ->
							paseto.decrypt(tv.getToken(), TokenTestVectors.TEST_V2_KEY, tv.getPayloadClass()),
					PasetoV1.HEADER_LOCAL, PasetoV2.HEADER_LOCAL);
		});
	}

	// Attempt to decrypt A V1 local token with as V2 public token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_v1LocalAsV2Public(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertInvalidHeaderException(() ->
							paseto.verify(tv.getToken(), TokenTestVectors.TEST_V2_PK, tv.getPayloadClass()),
					PasetoV1.HEADER_LOCAL, PasetoV2.HEADER_PUBLIC);
		});
	}

	// Attempt to decrypt A V1 public token with a V2 local token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_v1PublicAsV2Local(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertInvalidHeaderException(() ->
							paseto.decrypt(tv.getToken(), TokenTestVectors.TEST_V2_KEY, tv.getPayloadClass()),
					PasetoV1.HEADER_PUBLIC, PasetoV2.HEADER_LOCAL);
		});
	}

	// Attempt to decrypt A V1 public token with a V2 public token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_v1PublicAsV2Public(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertInvalidHeaderException(() ->
							paseto.verify(tv.getToken(), TokenTestVectors.TEST_V2_PK, tv.getPayloadClass()),
					PasetoV1.HEADER_PUBLIC, PasetoV2.HEADER_PUBLIC);
		});
	}

	// Attempt to verify A V2 local token as a V2 public token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_publicAsLocal(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertInvalidHeaderException(() ->
							paseto.decrypt(tv.getToken(), TokenTestVectors.TEST_V2_KEY, tv.getPayloadClass()),
					PasetoV2.HEADER_PUBLIC, PasetoV2.HEADER_LOCAL);
		});
	}

	// Attempt to verify A V2 public token as a V2 local token, should fail with a InvalidHeaderException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_localAsPublic(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidHeaderException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertInvalidHeaderException(() ->
							paseto.verify(tv.getToken(), TokenTestVectors.TEST_V2_PK, tv.getPayloadClass()),
					PasetoV2.HEADER_LOCAL, PasetoV2.HEADER_PUBLIC);
		});
	}

	// Attempt to verify local token with a missing footer, should fail with a InvalidFooterException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_localMissingFooter(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidFooterException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertInvalidFooterException(() ->
							paseto.decrypt(tv.getToken(), tv.getLocalKey(), "not-the-footer", tv.getPayloadClass()),
					"", "not-the-footer");
		});
	}

	// Attempt to verify public token with a missing footer, should fail with a InvalidFooterException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_publicMissingFooter(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidFooterException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_PUBLIC;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertInvalidFooterException(() ->
							paseto.verify(tv.getToken(), tv.getPublicKey(), "not-the-footer", tv.getPayloadClass()),
					"", "not-the-footer");
		});
	}

	// Attempt to verify local token with an incorrect footer, should fail with a InvalidFooterException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_localWrongFooter(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidFooterException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			String given = builder.encodingProvider.encode(tv.getFooter());
			AssertUtils.assertInvalidFooterException(() ->
							paseto.decrypt(tv.getToken(), tv.getLocalKey(), "not-the-footer", tv.getPayloadClass()),
					given, "not-the-footer");
		});
	}

	// Attempt to verify public token with an incorrect footer, should fail with a InvalidFooterException.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_publicWrongFooter(Paseto.Builder builder) {
		Assertions.assertThrows(InvalidFooterException.class, () -> {
			TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			String given = builder.encodingProvider.encode(tv.getFooter());
			AssertUtils.assertInvalidFooterException(() ->
							paseto.verify(tv.getToken(), tv.getPublicKey(), "not-the-footer", tv.getPayloadClass()),
					given, "not-the-footer");
		});
	}

	// Errors
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_badInput(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoStringException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertPasetoStringException(() ->
							paseto.decrypt("junk", tv.getLocalKey(), tv.getPayloadClass()),
					"junk");
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_badTokenDecrypt(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoStringException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertPasetoStringException(() ->
							paseto.decrypt("v2.local.", tv.getLocalKey(), tv.getPayloadClass()),
					"v2.local.");
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_badTokenVerify(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoStringException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertPasetoStringException(() ->
							paseto.verify("v2.local.", TokenTestVectors.TEST_V2_PK, tv.getPayloadClass()),
					"v2.local.");
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_shortTokenLocal(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoStringException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertPasetoStringException(() ->
							paseto.decrypt("v2.local.c29tZXRoaW5n", tv.getLocalKey(), tv.getPayloadClass()),
					"v2.local.c29tZXRoaW5n");
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_shortTokenPublic(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoStringException.class, () -> {
			TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_PUBLIC;
			Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
			AssertUtils.assertPasetoStringException(() ->
							paseto.verify("v2.public.c29tZXRoaW5n", tv.getPublicKey(), tv.getPayloadClass()),
					"v2.public.c29tZXRoaW5n");
		});
	}

	// Nonce tests
	// Generates a V2 Local token twice, the results should be different due to nonce rng.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token1_localNonce(Paseto.Builder builder) {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;
		Paseto paseto = builder.build();
		String token1 = paseto.encrypt(tv.getPayload(), tv.getLocalKey(), tv.getFooter());
		String token2 = paseto.encrypt(tv.getPayload(), tv.getLocalKey(), tv.getFooter());
		Assertions.assertNotEquals(token1, token2, "nonce failed, 2 tokens have same contents");
	}

	// Key pair generation tests
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_token2_generateKeyPair(Paseto.Builder builder) {
		Paseto paseto = builder.build();
		KeyPair keyPair = paseto.generateKeyPair();

		// encrypt with new key
		String token = paseto.sign(TokenTestVectors.TOKEN_2, keyPair.getSecretKey());
		// now decrypt, should work
		CustomToken payload = paseto.verify(token, keyPair.getPublicKey(), CustomToken.class);
		Assertions.assertEquals(TokenTestVectors.TOKEN_2, payload, "decrypted payload != original payload");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_local_parseException_missingSections(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoParseException.class, () -> {
			Paseto paseto = builder.build();

			AssertUtils.assertPasetoParseException(() ->
							paseto.decrypt("", RfcTestVectors.RFC_TEST_V2_KEY, RfcToken.class),
					"", PasetoParseException.Reason.MISSING_SECTIONS, 0);
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_public_parseException_missingSections(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoParseException.class, () -> {
			Paseto paseto = builder.build();

			AssertUtils.assertPasetoParseException(() ->
							paseto.verify("", RfcTestVectors.RFC_TEST_V2_PK, RfcToken.class),
					"", PasetoParseException.Reason.MISSING_SECTIONS, 0);
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_local_parseException_payloadLength(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoParseException.class, () -> {
			Paseto paseto = builder.build();

			AssertUtils.assertPasetoParseException(() ->
							paseto.decrypt("v2.local.aa", RfcTestVectors.RFC_TEST_V2_KEY, RfcToken.class),
					"v2.local.aa", PasetoParseException.Reason.PAYLOAD_LENGTH, 25);
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV2Builders")
	public void v2_public_parseException_payloadLength(Paseto.Builder builder) {
		Assertions.assertThrows(PasetoParseException.class, () -> {
			Paseto paseto = builder.build();

			AssertUtils.assertPasetoParseException(() ->
							paseto.verify("v2.public.aa", RfcTestVectors.RFC_TEST_V2_PK, RfcToken.class),
					"v2.public.aa", PasetoParseException.Reason.PAYLOAD_LENGTH, 65);
		});
	}

	@Test
	@DisplayName("V2 Builder has a default base 64 provider.")
	public void v2_builder_withDefaultBase64Provider() {
		PasetoV2.Builder builder = new PasetoV2.Builder();
		builder.build();
		Assertions.assertNotNull(builder.base64Provider);
	}

	@Test
	@DisplayName("V2 Builder can override base 64 provider.")
	public void v2_builder_withBase64Provider() {
		Base64Provider provider = new Jvm8Base64Provider();
		PasetoV2.Builder builder = new PasetoV2.Builder();
		builder.withBase64Provider(provider);
		Assertions.assertEquals(provider, builder.base64Provider);
	}

	@Test
	@DisplayName("V2 Builder has a default crypto provider.")
	public void v2_builder_withDefaultV2CryptoProvider() {
		PasetoV2.Builder builder = new PasetoV2.Builder();
		builder.build();
		Assertions.assertNotNull(builder.v2CryptoProvider);
	}

	@Test
	@DisplayName("V2 Builder can override crypto provider.")
	public void v2_builder_withV2CryptoProvider() {
		V2CryptoProvider provider = new BouncyCastleV2CryptoProvider();
		PasetoV2.Builder builder = new PasetoV2.Builder();
		builder.withV2CryptoProvider(provider);
		Assertions.assertEquals(provider, builder.v2CryptoProvider);
	}
}
