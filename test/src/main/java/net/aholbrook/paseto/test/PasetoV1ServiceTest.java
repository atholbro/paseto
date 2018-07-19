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

import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.test.data.RfcTestVectors;
import net.aholbrook.paseto.test.data.RfcToken;
import net.aholbrook.paseto.test.data.TestVector;
import org.junit.Test;

public class PasetoV1ServiceTest extends PasetoServiceTest {
	private static LocalTokenService.KeyProvider rfcLocalKeyProvider() {
		return RfcTestVectors::rfcTestKey;
	}

	private static PublicTokenService.KeyProvider rfcPublicKeyProvider() {
		return new PublicTokenService.KeyProvider() {
			@Override
			public byte[] getSecretKey() {
				return RfcTestVectors.rfcTestV1PrivateKey();
			}

			@Override
			public byte[] getPublicKey() {
				return RfcTestVectors.rfcTestV1PublicKey();
			}
		};
	}

	private static TokenService<RfcToken> rfcLocalService(byte[] nonce) {
		return TestBuilders.find().localServiceBuilderV1(nonce, rfcLocalKeyProvider(), RfcToken.class)
				.checkClaims(new Claim[] {})
				.build();
	}

	private static TokenService<RfcToken> rfcPublicService() {
		return TestBuilders.find().publicServiceBuilderV1(rfcPublicKeyProvider(), RfcToken.class)
				.checkClaims(new Claim[] {})
				.build();
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
}
