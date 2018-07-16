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

import net.aholbrook.paseto.test.data.RfcTestVectors;
import org.junit.Test;

public abstract class PasetoV2TestBase extends PasetoTestBase {
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
}
