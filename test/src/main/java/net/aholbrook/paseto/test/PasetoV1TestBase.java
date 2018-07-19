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
import net.aholbrook.paseto.crypto.base.Tuple;
import net.aholbrook.paseto.exception.InvalidFooterException;
import net.aholbrook.paseto.exception.InvalidHeaderException;
import net.aholbrook.paseto.exception.PasetoStringException;
import net.aholbrook.paseto.exception.SignatureVerificationException;
import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.test.data.RfcTestVectors;
import net.aholbrook.paseto.test.data.TestVector;
import net.aholbrook.paseto.test.data.TokenTestVectors;
import net.aholbrook.paseto.util.StringUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.Charset;

public abstract class PasetoV1TestBase extends PasetoTestBase {
	// RFC test vectors
	// Encryption tests
	@Test
	public void v1_RfcVectorE1() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_1);
	}

	@Test
	public void v1_RfcVectorE2() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_2);
	}

	@Test
	public void v1_RfcVectorE3() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_3);
	}

	@Test
	public void v1_RfcVectorE4() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_4);
	}

	@Test
	public void v1_RfcVectorE5() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_5);
	}

	@Test
	public void v1_RfcVectorE6() {
		encryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_6);
	}

	// Decryption tests
	@Test
	public void v1_RfcVectorE1Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_1);
	}

	@Test
	public void v1_RfcVectorE2Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_2);
	}

	@Test
	public void v1_RfcVectorE3Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_3);
	}

	@Test
	public void v1_RfcVectorE4Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_4);
	}

	@Test
	public void v1_RfcVectorE5Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_5);
	}

	@Test
	public void v1_RfcVectorE6Decrypt() {
		decryptTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_E_6);
	}

	// Sign tests
	@Test
	public void v1_RfcVectorS1Sign() {
		signTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_S_1, false);
	}

	@Test
	public void v1_RfcVectorS2Sign() {
		signTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_S_2, false);
	}

	// Verify tests
	@Test
	public void v1_RfcVectorS1Verify() {
		verifyTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_S_1);
	}

	@Test
	public void v1_RfcVectorS2Verify() {
		verifyTestVector(RfcTestVectors.RFC_TEST_VECTOR_V1_S_2);
	}

	// Other test vectors
	// Encryption tests
	@Test
	public void v1_token1Local() {
		encryptTestVector(TokenTestVectors.TV_1_V1_LOCAL);
	}

	@Test
	public void v1_token1LocalWithFooter() {
		encryptTestVector(TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v1_token2Local() {
		encryptTestVector(TokenTestVectors.TV_2_V1_LOCAL);
	}

	@Test
	public void v1_token2LocalWithFooter() {
		encryptTestVector(TokenTestVectors.TV_2_V1_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v1_token3Local() {
		encryptTestVector(TokenTestVectors.TV_3_V1_LOCAL);
	}

	@Test
	public void v1_token3LocalWithFooter() {
		encryptTestVector(TokenTestVectors.TV_3_V1_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v1_token4Local() {
		encryptTestVector(TokenTestVectors.TV_4_V1_LOCAL);
	}

	@Test
	public void v1_token4LocalWithFooter() {
		encryptTestVector(TokenTestVectors.TV_4_V1_LOCAL_WITH_FOOTER);
	}

	// Decryption tests
	@Test
	public void v1_token1LocalDecrypt() {
		decryptTestVector(TokenTestVectors.TV_1_V1_LOCAL);
	}

	@Test
	public void v1_token1LocalWithFooterDecrypt() {
		decryptTestVector(TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v1_token2LocalDecrypt() {
		decryptTestVector(TokenTestVectors.TV_2_V1_LOCAL);
	}

	@Test
	public void v1_token2LocalWithFooterDecrypt() {
		decryptTestVector(TokenTestVectors.TV_2_V1_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v1_token3LocalDecrypt() {
		decryptTestVector(TokenTestVectors.TV_3_V1_LOCAL);
	}

	@Test
	public void v1_token3LocalWithFooterDecrypt() {
		decryptTestVector(TokenTestVectors.TV_3_V1_LOCAL_WITH_FOOTER);
	}

	@Test
	public void v1_token4LocalDecrypt() {
		decryptTestVector(TokenTestVectors.TV_4_V1_LOCAL);
	}

	@Test
	public void v1_token4LocalWithFooterDecrypt() {
		decryptTestVector(TokenTestVectors.TV_4_V1_LOCAL_WITH_FOOTER);
	}

	// Sign tests
	@Test
	public void v1_token1Public() {
		signTestVector(TokenTestVectors.TV_1_V1_PUBLIC, false);
	}

	@Test
	public void v1_token1PublicWithFooter() {
		signTestVector(TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER, false);
	}

	@Test
	public void v1_token2Public() {
		signTestVector(TokenTestVectors.TV_2_V1_PUBLIC, false);
	}

	@Test
	public void v1_token2PublicWithFooter() {
		signTestVector(TokenTestVectors.TV_2_V1_PUBLIC_WITH_FOOTER, false);
	}

	@Test
	public void v1_token3Public() {
		signTestVector(TokenTestVectors.TV_3_V1_PUBLIC, false);
	}

	@Test
	public void v1_token3PublicWithFooter() {
		signTestVector(TokenTestVectors.TV_3_V1_PUBLIC_WITH_FOOTER, false);
	}

	@Test
	public void v1_token4Public() {
		signTestVector(TokenTestVectors.TV_4_V1_PUBLIC, false);
	}

	@Test
	public void v1_token4PublicWithFooter() {
		signTestVector(TokenTestVectors.TV_4_V1_PUBLIC_WITH_FOOTER, false);
	}

	// Verify tests
	@Test
	public void v1_token1PublicVerify() {
		verifyTestVector(TokenTestVectors.TV_1_V1_PUBLIC);
	}

	@Test
	public void v1_token1PublicWithFooterVerify() {
		verifyTestVector(TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER);
	}

	@Test
	public void v1_token2PublicVerify() {
		verifyTestVector(TokenTestVectors.TV_2_V1_PUBLIC);
	}

	@Test
	public void v1_token2PublicWithFooterVerify() {
		verifyTestVector(TokenTestVectors.TV_2_V1_PUBLIC_WITH_FOOTER);
	}

	@Test
	public void v1_token3PublicVerify() {
		verifyTestVector(TokenTestVectors.TV_3_V1_PUBLIC);
	}

	@Test
	public void v1_token3PublicWithFooterVerify() {
		verifyTestVector(TokenTestVectors.TV_3_V1_PUBLIC_WITH_FOOTER);
	}

	@Test
	public void v1_token4PublicVerify() {
		verifyTestVector(TokenTestVectors.TV_4_V1_PUBLIC);
	}

	@Test
	public void v1_token4PublicWithFooterVerify() {
		verifyTestVector(TokenTestVectors.TV_4_V1_PUBLIC_WITH_FOOTER);
	}

	// Footer extraction tests
	@Test
	public void v1_token1_extractFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto<Token> paseto = createPaseto();

		KeyId footer = paseto.extractFooter(tv.getToken(), KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), footer);
	}

	@Test
	public void v1_token1_extractFooterString() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto<Token> paseto = createPaseto();

		String footerString = paseto.extractFooter(tv.getToken());
		KeyId footer = encodingProvider().fromJson(footerString, KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), footer);
	}

	@Test
	public void v1_token1_extractMissingFooter() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_PUBLIC;
		Paseto<Token> paseto = createPaseto();

		KeyId footer = paseto.extractFooter(tv.getToken(), KeyId.class);
		Assert.assertNull("footer not null", footer);
	}

	@Test
	public void v1_token1_localDecryptWithFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		Paseto<Token> paseto = createPaseto(tv.getB());

		Tuple<Token, KeyId> result = paseto.decryptWithFooter(tv.getToken(), tv.getA(), tv.getPayloadClass(),
				KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), result.b);
	}

	@Test
	public void v1_token1_localDecryptWithFooterString() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		Paseto<Token> paseto = createPaseto(tv.getB());

		Tuple<Token, String> result = paseto.decryptWithFooter(tv.getToken(), tv.getA(), tv.getPayloadClass());
		KeyId footer = encodingProvider().fromJson(result.b, KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), footer);
	}

	@Test
	public void v1_token1_publicVerifyWithFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto<Token> paseto = createPaseto(tv.getB());

		Tuple<Token, KeyId> result = paseto.verifyWithFooter(tv.getToken(), tv.getB(), tv.getPayloadClass(),
				KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), result.b);
	}

	@Test
	public void v1_token1_publicVerifyWithFooterString() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto<Token> paseto = createPaseto(tv.getB());

		Tuple<Token, String> result = paseto.verifyWithFooter(tv.getToken(), tv.getB(), tv.getPayloadClass());
		KeyId footer = encodingProvider().fromJson(result.b, KeyId.class);
		Assert.assertEquals("extracted footer != footer", tv.getFooter(), footer);
	}

	// Modification / tampering tests
	// Modify the token contents after encryption, then try to decrypt, should produce a SignatureVerificationException.
	@Test(expected = SignatureVerificationException.class)
	public void v1_token1_modifyPayload() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
		Paseto<Token> paseto = createPaseto(tv.getB());

		// encrypt and modify
		String token = paseto.encrypt(tv.getPayload(), tv.getA());
		token = modify(token, new int[] { 20, 15, 20 });

		// attempt to decrypt
		paseto.decrypt(token, tv.getA(), tv.getPayloadClass());
	}

	// Modify the token footer after encryption, then try to decrypt, should produce a SignatureVerificationException.
	@Test(expected = SignatureVerificationException.class)
	public void v1_token1_modifyFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		Paseto<Token> paseto = createPaseto(tv.getB());

		// encrypt and modify
		String token = paseto.encrypt(tv.getPayload(), tv.getA());
		token = modify(token, new int[] { token.length() - 1, token.length() - 4, token.length() - 6 });

		// attempt to decrypt
		paseto.decrypt(token, tv.getA(), tv.getPayloadClass());
	}

	// Decrypt with a different key, should fail with a SignatureVerificationException
	@Test(expected = SignatureVerificationException.class)
	public void v1_token1_decryptWrongKey() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
		Paseto<Token> paseto = createPaseto(tv.getB());

		// attempt to decrypt
		paseto.decrypt(tv.getToken(), RfcTestVectors.rfcTestKey(), tv.getPayloadClass());
	}

	// Verify with a different public key, should fail with a SignatureVerificationException
	@Test(expected = SignatureVerificationException.class)
	public void v1_token1_verifyWrongKey() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_PUBLIC;
		Paseto<Token> paseto = createPaseto(tv.getB());

		// attempt to decrypt
		paseto.verify(tv.getToken(), RfcTestVectors.rfcTestV1PublicKey(), tv.getPayloadClass());
	}

	// Attempt to decrypt A V2 local token with as V1 local token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v1_token1_v2LocalAsV1Local() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;

		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.decrypt(tv.getToken(), tv.getA(), tv.getPayloadClass());
	}

	// Attempt to decrypt A V2 local token with as V1 public token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v1_token1_v2LocalAsV1Public() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_LOCAL_WITH_FOOTER;

		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.verify(tv.getToken(), tv.getA(), tv.getPayloadClass());
	}

	// Attempt to decrypt A V2 public token with a V1 local token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v1_token1_v2PublicAsV1Local() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;

		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.decrypt(tv.getToken(), tv.getA(), tv.getPayloadClass());
	}

	// Attempt to decrypt A V2 public token with a V1 public token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v1_token1_v2PublicAsV1Public() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V2_PUBLIC_WITH_FOOTER;

		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.verify(tv.getToken(), tv.getA(), tv.getPayloadClass());
	}

	// Attempt to verify A V1 local token as a V1 public token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v1_token1_publicAsLocal() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;

		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.decrypt(tv.getToken(), tv.getA(), tv.getPayloadClass());
	}

	// Attempt to verify A V1 public token as a V1 local token, should fail with a InvalidHeaderException.
	@Test(expected = InvalidHeaderException.class)
	public void v1_token1_localAsPublic() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;

		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.verify(tv.getToken(), tv.getA(), tv.getPayloadClass());
	}

	// Attempt to verify local token with a missing footer, should fail with a InvalidFooterException.
	@Test(expected = InvalidFooterException.class)
	public void v1_token1_localMissingFooter() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;

		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.decrypt(tv.getToken(), tv.getA(), "not-the-footer", tv.getPayloadClass());
	}

	// Attempt to verify public token with a missing footer, should fail with a InvalidFooterException.
	@Test(expected = InvalidFooterException.class)
	public void v1_token1_publicMissingFooter() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_PUBLIC;

		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.verify(tv.getToken(), tv.getA(), "not-the-footer", tv.getPayloadClass());
	}

	// Attempt to verify local token with an incorrect footer, should fail with a InvalidFooterException.
	@Test(expected = InvalidFooterException.class)
	public void v1_token1_localWrongFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;

		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.decrypt(tv.getToken(), tv.getA(), "not-the-footer", tv.getPayloadClass());
	}

	// Attempt to verify public token with an incorrect footer, should fail with a InvalidFooterException.
	@Test(expected = InvalidFooterException.class)
	public void v1_token1_publicWrongFooter() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;

		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.verify(tv.getToken(), tv.getA(), "not-the-footer", tv.getPayloadClass());
	}

	// Errors
	@Test(expected = PasetoStringException.class)
	public void v1_badInput() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.decrypt("junk", tv.getA(), tv.getPayloadClass());
	}

	@Test(expected = PasetoStringException.class)
	public void v1_badTokenDecrypt() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.decrypt("v1.local.", tv.getA(), tv.getPayloadClass());
	}

	@Test(expected = PasetoStringException.class)
	public void v1_badTokenVerify() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.verify("v1.local.", tv.getA(), tv.getPayloadClass());
	}

	@Test(expected = PasetoStringException.class)
	public void v1_shortTokenLocal() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_LOCAL;
		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.decrypt("v1.local.c29tZXRoaW5n", tv.getA(), tv.getPayloadClass());
	}

	@Test(expected = PasetoStringException.class)
	public void v1_shortTokenPublic() {
		TestVector<Token, Void> tv = TokenTestVectors.TV_1_V1_PUBLIC;
		Paseto<Token> paseto = createPaseto(tv.getB());
		paseto.verify("v1.public.c29tZXRoaW5n", tv.getA(), tv.getPayloadClass());
	}

	// Nonce tests
	// Generates a V1 Local token twice, the results should be different due to nonce rng.
	@Test
	public void v1_token1_localNonce() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_LOCAL_WITH_FOOTER;
		Paseto<Token> paseto = createPaseto();
		String token1 = paseto.encrypt(tv.getPayload(), tv.getA(), tv.getFooter());
		String token2 = paseto.encrypt(tv.getPayload(), tv.getA(), tv.getFooter());
		Assert.assertNotEquals("nonce failed, 2 tokens have same contents", token1, token2);
	}

	@Test
	public void v1_token1_publicNonce() {
		TestVector<Token, KeyId> tv = TokenTestVectors.TV_1_V1_PUBLIC_WITH_FOOTER;
		Paseto<Token> paseto = createPaseto();
		String token1 = paseto.encrypt(tv.getPayload(), tv.getA(), tv.getFooter());
		String token2 = paseto.encrypt(tv.getPayload(), tv.getA(), tv.getFooter());
		Assert.assertNotEquals("nonce failed, 2 tokens have same contents", token1, token2);
	}

	// Key pair generation tests
	@Test
	public void v1_token1_generateKeyPair() {
		Paseto<Token> paseto = createPaseto();
		Tuple<byte[], byte[]> keyPair = paseto.generateKeyPair();

		// encrypt with new key
		String token = paseto.sign(TokenTestVectors.TOKEN_1, keyPair.a);
		// now decrypt, should work
		Token payload = paseto.verify(token, keyPair.b, Token.class);
		Assert.assertEquals("decrypted payload != original payload", TokenTestVectors.TOKEN_1, payload);
	}
}
