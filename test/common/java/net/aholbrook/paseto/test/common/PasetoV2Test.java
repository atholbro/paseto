package net.aholbrook.paseto.test.common;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.PasetoV1;
import net.aholbrook.paseto.PasetoV2;
import net.aholbrook.paseto.TokenWithFooter;
import net.aholbrook.paseto.crypto.KeyPair;
import net.aholbrook.paseto.encoding.EncodingLoader;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.exception.DecryptionException;
import net.aholbrook.paseto.exception.InvalidFooterException;
import net.aholbrook.paseto.exception.InvalidHeaderException;
import net.aholbrook.paseto.exception.PasetoParseException;
import net.aholbrook.paseto.exception.PasetoStringException;
import net.aholbrook.paseto.exception.SignatureVerificationException;
import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.test.common.crypto.TestNonceGenerator;
import net.aholbrook.paseto.test.common.data.CustomToken;
import net.aholbrook.paseto.test.common.data.RfcTestVectors;
import net.aholbrook.paseto.test.common.data.RfcToken;
import net.aholbrook.paseto.test.common.data.TestVector;
import net.aholbrook.paseto.test.common.data.TokenTestVectors;
import net.aholbrook.paseto.test.common.utils.AssertUtils;
import org.junit.Assert;
import org.junit.Test;

public class PasetoV2Test extends PasetoTest {
	@Override
	protected Paseto createPaseto(byte[] nonce) {
		PasetoV2.Builder builder = new PasetoV2.Builder();
		if (nonce != null) { builder.withTestingNonceGenerator(new TestNonceGenerator(nonce)); }
		return builder.build();
	}

	// RFC test vectors
	// Encryption tests
	@Test
	public void v2_RfcVectorE1() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_1);
	}

	@Test
	public void v2_RfcVectorE2() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_2);
	}

	@Test
	public void v2_RfcVectorE3() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_3);
	}

	@Test
	public void v2_RfcVectorE4() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_4);
	}

	@Test
	public void v2_RfcVectorE5() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_5);
	}

	@Test
	public void v2_RfcVectorE6() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_6);
	}

	// Decryption tests
	@Test
	public void v2_RfcVectorE1Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_1);
	}

	@Test
	public void v2_RfcVectorE2Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_2);
	}

	@Test
	public void v2_RfcVectorE3Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_3);
	}

	@Test
	public void v2_RfcVectorE4Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_4);
	}

	@Test
	public void v2_RfcVectorE5Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_5);
	}

	@Test
	public void v2_RfcVectorE6Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_E_6);
	}

	// Sign tests
	@Test
	public void v2_RfcVectorS1Sign() {
		signTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_S_1, true);
	}

	@Test
	public void v2_RfcVectorS2Sign() {
		signTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_S_2, true);
	}

	// Verify tests
	@Test
	public void v2_RfcVectorS1Verify() {
		verifyTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_S_1);
	}

	@Test
	public void v2_RfcVectorS2Verify() {
		verifyTestVector(RfcTestVectors.RFC_TEST_VECTOR_V2_S_2);
	}

	// Other test vectors
	// Encryption tests
	@Test
	public void v2_token1Local() {
		encryptTestVector(TokenTestVectors.TV_1_V2_LOCAL);
	}

	@Test
	public void v2_token1LocalWithFooter() {
		encryptTestVector(TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v2_token1LocalWithStringFooter() {
		encryptTestVector(TokenTestVectors.TV_1_V2_LOCAL_WITH_STRING_FOOTER);
	}

	@Test
	public void v2_token2Local() {
		encryptTestVector(TokenTestVectors.TV_2_V2_LOCAL);
	}

	@Test
	public void v2_token2LocalWithFooter() {
		encryptTestVector(TokenTestVectors.TV_2_V2_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v2_token3Local() {
		encryptTestVector(TokenTestVectors.TV_3_V2_LOCAL);
	}

	@Test
	public void v2_token3LocalWithFooter() {
		encryptTestVector(TokenTestVectors.TV_3_V2_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v2_token4Local() {
		encryptTestVector(TokenTestVectors.TV_4_V2_LOCAL);
	}

	@Test
	public void v2_token4LocalWithFooter() {
		encryptTestVector(TokenTestVectors.TV_4_V2_LOCAL_WITH_FOOTER);
	}

	// Decryption tests
	@Test
	public void v2_token1LocalDecrypt() {
		decryptTestVector(TokenTestVectors.TV_1_V2_LOCAL);
	}

	@Test
	public void v2_token1LocalWithFooterDecrypt() {
		decryptTestVector(TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v2_token1LocalWithStringFooterDecrypt() {
		decryptTestVector(TokenTestVectors.TV_1_V2_LOCAL_WITH_STRING_FOOTER);
	}

	@Test
	public void v2_token2LocalDecrypt() {
		decryptTestVector(TokenTestVectors.TV_2_V2_LOCAL);
	}

	@Test
	public void v2_token2LocalWithFooterDecrypt() {
		decryptTestVector(TokenTestVectors.TV_2_V2_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v2_token3LocalDecrypt() {
		decryptTestVector(TokenTestVectors.TV_3_V2_LOCAL);
	}

	@Test
	public void v2_token3LocalWithFooterDecrypt() {
		decryptTestVector(TokenTestVectors.TV_3_V2_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v2_token4LocalDecrypt() {
		decryptTestVector(TokenTestVectors.TV_4_V2_LOCAL);
	}

	@Test
	public void v2_token4LocalWithFooterDecrypt() {
		decryptTestVector(TokenTestVectors.TV_4_V2_LOCAL_WITH_FOOTER);
	}

	// Sign tests
	@Test
	public void v2_token1Public() {
		signTestVector(TokenTestVectors.TV_1_V2_PUBLIC, true);
	}

	@Test
	public void v2_token1PublicWithFooter() {
		signTestVector(TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER, true);
	}

	@Test
	public void v2_token1PublicWithStringFooter() {
		signTestVector(TokenTestVectors.TV_1_V2_PUBLIC_WITH_STRING_FOOTER, true);
	}

	@Test
	public void v2_token2Public() {
		signTestVector(TokenTestVectors.TV_2_V2_PUBLIC, true);
	}

	@Test
	public void v2_token2PublicWithFooter() {
		signTestVector(TokenTestVectors.TV_2_V2_PUBLIC_WITH_FOOTER, true);
	}

	@Test
	public void v2_token3Public() {
		signTestVector(TokenTestVectors.TV_3_V2_PUBLIC, true);
	}

	@Test
	public void v2_token3PublicWithFooter() {
		signTestVector(TokenTestVectors.TV_3_V2_PUBLIC_WITH_FOOTER, true);
	}

	@Test
	public void v2_token4Public() {
		signTestVector(TokenTestVectors.TV_4_V2_PUBLIC, true);
	}

	@Test
	public void v2_token4PublicWithFooter() {
		signTestVector(TokenTestVectors.TV_4_V2_PUBLIC_WITH_FOOTER, true);
	}

	// Verify tests
	@Test
	public void v2_token1PublicVerify() {
		verifyTestVector(TokenTestVectors.TV_1_V2_PUBLIC);
	}

	@Test
	public void v2_token1PublicWithFooterVerify() {
		verifyTestVector(TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER);
	}

	@Test
	public void v2_token1PublicWithStringFooterVerify() {
		verifyTestVector(TokenTestVectors.TV_1_V2_PUBLIC_WITH_STRING_FOOTER);
	}

	@Test
	public void v2_token2PublicVerify() {
		verifyTestVector(TokenTestVectors.TV_2_V2_PUBLIC);
	}

	@Test
	public void v2_token2PublicWithFooterVerify() {
		verifyTestVector(TokenTestVectors.TV_2_V2_PUBLIC_WITH_FOOTER);
	}

	@Test
	public void v2_token3PublicVerify() {
		verifyTestVector(TokenTestVectors.TV_3_V2_PUBLIC);
	}

	@Test
	public void v2_token3PublicWithFooterVerify() {
		verifyTestVector(TokenTestVectors.TV_3_V2_PUBLIC_WITH_FOOTER);
	}

	@Test
	public void v2_token4PublicVerify() {
		verifyTestVector(TokenTestVectors.TV_4_V2_PUBLIC);
	}

	@Test
	public void v2_token4PublicWithFooterVerify() {
		verifyTestVector(TokenTestVectors.TV_4_V2_PUBLIC_WITH_FOOTER);
	}

	// Footer extraction tests
	@Test
	public void v2_token1_extractFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = createPaseto(null);

		KeyId footer = paseto.extractFooter(tv.getToken(), KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), footer);
	}

	@Test
	public void v2_token1_extractFooterString() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = createPaseto(null);

		String footerString = paseto.extractFooter(tv.getToken());
		KeyId footer = encodingProvider().decode(footerString, KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), footer);
	}

	@Test
	public void v2_token1_extractMissingFooter() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_PUBLIC;
		Paseto paseto = createPaseto(null);

		KeyId footer = paseto.extractFooter(tv.getToken(), KeyId.class);
		Assert.assertNull("footer not null", footer);
	}

	@Test
	public void v2_token1_localDecryptWithFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());

		TokenWithFooter<Token, KeyId> result = paseto.decryptWithFooter(tv.getToken(), tv.getA(), tv.getPayloadClass(),
				KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), result.getFooter());
	}

	@Test
	public void v2_token1_localDecryptWithFooterString() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());

		TokenWithFooter<Token, String> result = paseto.decryptWithFooter(tv.getToken(), tv.getA(), tv.getPayloadClass());
		KeyId footer = encodingProvider().decode(result.getFooter(), KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), footer);
	}

	@Test
	public void v1_token1_publicVerifyWithFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());

		TokenWithFooter<Token, KeyId> result = paseto.verifyWithFooter(tv.getToken(), tv.getB(), tv.getPayloadClass(),
				KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), result.getFooter());
	}

	@Test
	public void v2_token1_publicVerifyWithFooterString() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());

		TokenWithFooter<Token, String> result = paseto.verifyWithFooter(tv.getToken(), tv.getB(), tv.getPayloadClass());
		KeyId footer = encodingProvider().decode(result.getFooter(), KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), footer);
	}

	// Modification / tampering tests
	// Modify the token contents after encryption, then try to decrypt, should produce a DecryptionException.
	@Test(expected = DecryptionException.class)
	public void v2_token1_modifyPayload() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
		Paseto paseto = createPaseto(tv.getB());

		// encrypt and modify
		String token = paseto.encrypt(tv.getPayload(), tv.getA());
		token = modify(token, new int[] {20, 15, 20});

		// attempt to decrypt
		paseto.decrypt(token, tv.getA(), tv.getPayloadClass());
	}

	// Modify the token footer after encryption, then try to decrypt, should produce a DecryptionException.
	@Test(expected = DecryptionException.class)
	public void v2_token1_modifyFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());

		// encrypt and modify
		String token = paseto.encrypt(tv.getPayload(), tv.getA());
		token = modify(token, new int[] {token.length() - 1, token.length() - 4, token.length() - 6});

		// attempt to decrypt
		paseto.decrypt(token, tv.getA(), tv.getPayloadClass());
	}

	// Decrypt with a different key, should fail with a DecryptionException
	@Test(expected = DecryptionException.class)
	public void v2_token1_decryptWrongKey() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
		Paseto paseto = createPaseto(tv.getB());

		// attempt to decrypt
		paseto.decrypt(tv.getToken(), RfcTestVectors.RFC_TEST_KEY, tv.getPayloadClass());
	}

	// Verify with a different public key, should fail with a SignatureVerificationException
	@Test(expected = SignatureVerificationException.class)
	public void v2_token1_verifyWrongKey() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_PUBLIC;
		Paseto paseto = createPaseto(tv.getB());

		// attempt to decrypt
		paseto.verify(tv.getToken(), RfcTestVectors.RFC_TEST_PK, tv.getPayloadClass());
	}

	// Attempt to decrypt A V1 local token with as V2 local token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v2_token1_v1LocalAsV2Local() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertInvalidHeaderException(() ->
						paseto.decrypt(tv.getToken(), tv.getA(), tv.getPayloadClass()),
				PasetoV1.HEADER_LOCAL, PasetoV2.HEADER_LOCAL);
	}

	// Attempt to decrypt A V1 local token with as V2 public token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v2_token1_v1LocalAsV2Public() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertInvalidHeaderException(() ->
						paseto.verify(tv.getToken(), tv.getA(), tv.getPayloadClass()),
				PasetoV1.HEADER_LOCAL, PasetoV2.HEADER_PUBLIC);
	}

	// Attempt to decrypt A V1 public token with a V2 local token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v2_token1_v1PublicAsV2Local() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertInvalidHeaderException(() ->
						paseto.decrypt(tv.getToken(), tv.getA(), tv.getPayloadClass()),
				PasetoV1.HEADER_PUBLIC, PasetoV2.HEADER_LOCAL);
	}

	// Attempt to decrypt A V1 public token with a V2 public token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v2_token1_v1PublicAsV2Public() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertInvalidHeaderException(() ->
						paseto.verify(tv.getToken(), tv.getA(), tv.getPayloadClass()),
				PasetoV1.HEADER_PUBLIC, PasetoV2.HEADER_PUBLIC);
	}

	// Attempt to verify A V2 local token as a V2 public token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v2_token1_publicAsLocal() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertInvalidHeaderException(() ->
						paseto.decrypt(tv.getToken(), tv.getA(), tv.getPayloadClass()),
				PasetoV2.HEADER_PUBLIC, PasetoV2.HEADER_LOCAL);
	}

	// Attempt to verify A V2 public token as a V2 local token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v2_token1_localAsPublic() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertInvalidHeaderException(() ->
						paseto.verify(tv.getToken(), tv.getA(), tv.getPayloadClass()),
				PasetoV2.HEADER_LOCAL, PasetoV2.HEADER_PUBLIC);
	}

	// Attempt to verify local token with a missing footer, should fail with a InvalidFooterException.
	@Test(expected = InvalidFooterException.class)
	public void v2_token1_localMissingFooter() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertInvalidFooterException(() ->
						paseto.decrypt(tv.getToken(), tv.getA(), "not-the-footer", tv.getPayloadClass()),
				"", "not-the-footer");
	}

	// Attempt to verify public token with a missing footer, should fail with a InvalidFooterException.
	@Test(expected = InvalidFooterException.class)
	public void v2_token1_publicMissingFooter() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_PUBLIC;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertInvalidFooterException(() ->
						paseto.verify(tv.getToken(), tv.getA(), "not-the-footer", tv.getPayloadClass()),
				"", "not-the-footer");
	}

	// Attempt to verify local token with an incorrect footer, should fail with a InvalidFooterException.
	@Test(expected = InvalidFooterException.class)
	public void v2_token1_localWrongFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());
		String given = encodingProvider().encode(tv.getFooter());
		AssertUtils.assertInvalidFooterException(() ->
						paseto.decrypt(tv.getToken(), tv.getA(), "not-the-footer", tv.getPayloadClass()),
				given, "not-the-footer");
	}

	// Attempt to verify public token with an incorrect footer, should fail with a InvalidFooterException.
	@Test(expected = InvalidFooterException.class)
	public void v2_token1_publicWrongFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = createPaseto(tv.getB());
		String given = encodingProvider().encode(tv.getFooter());
		AssertUtils.assertInvalidFooterException(() ->
						paseto.verify(tv.getToken(), tv.getA(), "not-the-footer", tv.getPayloadClass()),
				given, "not-the-footer");
	}

	// Errors
	@Test(expected = PasetoStringException.class)
	public void v2_badInput() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertPasetoStringException(() ->
						paseto.decrypt("junk", tv.getA(), tv.getPayloadClass()),
				"junk");
	}

	@Test(expected = PasetoStringException.class)
	public void v2_badTokenDecrypt() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertPasetoStringException(() ->
						paseto.decrypt("v2.local.", tv.getA(), tv.getPayloadClass()),
				"v2.local.");
	}

	@Test(expected = PasetoStringException.class)
	public void v2_badTokenVerify() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertPasetoStringException(() ->
						paseto.verify("v2.local.", tv.getA(), tv.getPayloadClass()),
				"v2.local.");
	}

	@Test(expected = PasetoStringException.class)
	public void v2_shortTokenLocal() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_LOCAL;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertPasetoStringException(() ->
						paseto.decrypt("v2.local.c29tZXRoaW5n", tv.getA(), tv.getPayloadClass()),
				"v2.local.c29tZXRoaW5n");
	}

	@Test(expected = PasetoStringException.class)
	public void v2_shortTokenPublic() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V2_PUBLIC;
		Paseto paseto = createPaseto(tv.getB());
		AssertUtils.assertPasetoStringException(() ->
						paseto.verify("v2.public.c29tZXRoaW5n", tv.getA(), tv.getPayloadClass()),
				"v2.public.c29tZXRoaW5n");
	}

	// Nonce tests
	// Generates a V2 Local token twice, the results should be different due to nonce rng.
	@Test
	public void v2_token1_localNonce() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;
		Paseto paseto = createPaseto(null);
		String token1 = paseto.encrypt(tv.getPayload(), tv.getA(), tv.getFooter());
		String token2 = paseto.encrypt(tv.getPayload(), tv.getA(), tv.getFooter());
		Assert.assertNotEquals("nonce failed, 2 tokens have same contents", token1, token2);
	}

	@Test
	public void v2_token1_publicNonce() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;
		Paseto paseto = createPaseto(null);
		String token1 = paseto.encrypt(tv.getPayload(), tv.getA(), tv.getFooter());
		String token2 = paseto.encrypt(tv.getPayload(), tv.getA(), tv.getFooter());
		Assert.assertNotEquals("nonce failed, 2 tokens have same contents", token1, token2);
	}

	// Key pair generation tests
	@Test
	public void v2_token2_generateKeyPair() {
		Paseto paseto = createPaseto(null);
		KeyPair keyPair = paseto.generateKeyPair();

		// encrypt with new key
		String token = paseto.sign(TokenTestVectors.TOKEN_2, keyPair.getSecretKey());
		// now decrypt, should work
		CustomToken payload = paseto.verify(token, keyPair.getPublicKey(), CustomToken.class);
		Assert.assertEquals("decrypted payload != original payload", TokenTestVectors.TOKEN_2, payload);
	}

	@Test(expected = PasetoParseException.class)
	public void v2_local_parseException_missingSections() {
		Paseto paseto = createPaseto(null);

		AssertUtils.assertPasetoParseException(() ->
						paseto.decrypt("", RfcTestVectors.RFC_TEST_KEY, RfcToken.class),
				"", PasetoParseException.Reason.MISSING_SECTIONS, 0);
	}

	@Test(expected = PasetoParseException.class)
	public void v2_public_parseException_missingSections() {
		Paseto paseto = createPaseto(null);

		AssertUtils.assertPasetoParseException(() ->
						paseto.verify("", RfcTestVectors.RFC_TEST_PK, RfcToken.class),
				"", PasetoParseException.Reason.MISSING_SECTIONS, 0);
	}

	@Test(expected = PasetoParseException.class)
	public void v2_local_parseException_payloadLength() {
		Paseto paseto = createPaseto(null);

		AssertUtils.assertPasetoParseException(() ->
						paseto.decrypt("v2.local.aa", RfcTestVectors.RFC_TEST_KEY, RfcToken.class),
				"v2.local.aa", PasetoParseException.Reason.PAYLOAD_LENGTH, 25);
	}

	@Test(expected = PasetoParseException.class)
	public void v2_public_parseException_payloadLength() {
		Paseto paseto = createPaseto(null);

		AssertUtils.assertPasetoParseException(() ->
						paseto.verify("v2.public.aa", RfcTestVectors.RFC_TEST_PK, RfcToken.class),
				"v2.public.aa", PasetoParseException.Reason.PAYLOAD_LENGTH, 65);
	}
}
