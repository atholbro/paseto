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

import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.test.data.RfcTestVectors;
import net.aholbrook.paseto.test.data.RfcToken;
import net.aholbrook.paseto.test.data.TestVector;
import org.junit.Test;

public abstract class PasetoV2ServiceTestBase extends PasetoServiceTestBase {
	@Override
	protected LocalTokenService.KeyProvider localKeyProvider() {
		return RfcTestVectors::rfcTestKey;
	}

	@Override
	protected PublicTokenService.KeyProvider publicKeyProvider() {
		return new PublicTokenService.KeyProvider() {
			@Override
			public byte[] getSecretKey() {
				return RfcTestVectors.rfcTestV2SecretKey();
			}

			@Override
			public byte[] getPublicKey() {
				return RfcTestVectors.rfcTestV2PublicKey();
			}
		};
	}

	// Encryption tests
	@Test
	public void v2Service_rfcVectorE1() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_1;
		encodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	@Test
	public void v2Service_rfcVectorE2() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_2;
		encodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	@Test
	public void v2Service_rfcVectorE3() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_3;
		encodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	@Test
	public void v2Service_rfcVectorE4() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_4;
		encodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	@Test
	public void v2Service_rfcVectorE5() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_5;
		encodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	@Test
	public void v2Service_rfcVectorE6() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_6;
		encodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	// Decryption tests
	@Test
	public void v2Service_rfcVectorE1Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_1;
		decodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	@Test
	public void v2Service_rfcVectorE2Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_2;
		decodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	@Test
	public void v2Service_rfcVectorE3Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_3;
		decodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	@Test
	public void v2Service_rfcVectorE4Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_4;
		decodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	@Test
	public void v2Service_rfcVectorE5Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_5;
		decodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	@Test
	public void v2Service_rfcVectorE6Decrypt() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_E_6;
		decodeTestVector(createRfcLocal(tv.getB()), tv);
	}

	// Sign tests
	@Test
	public void v2Service_rfcVectorS1Sign() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_S_1;
		encodeTestVector(createRfcPublic(), tv);
	}

	@Test
	public void v2Service_rfcVectorS2Sign() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_S_2;
		encodeTestVector(createRfcPublic(), tv);
	}

	// Verify tests
	@Test
	public void v2Service_rfcVectorS1Verify() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_S_1;
		decodeTestVector(createRfcPublic(), tv);
	}

	@Test
	public void v2Service_rfcVectorS2Verify() {
		TestVector<RfcToken, ?> tv = RfcTestVectors.RFC_TEST_VECTOR_V2_S_2;
		decodeTestVector(createRfcPublic(), tv);
	}
}
