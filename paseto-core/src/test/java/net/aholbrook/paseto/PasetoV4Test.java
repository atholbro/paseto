package net.aholbrook.paseto;

import net.aholbrook.paseto.data.RfcTestVectors;
import net.aholbrook.paseto.exception.KeyVersionException;
import net.aholbrook.paseto.exception.PasetoParseException;
import net.aholbrook.paseto.exception.SignatureVerificationException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentest4j.AssertionFailedError;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class PasetoV4Test extends PasetoTest {
// RFC v4 test vectors

	// ------------- Encryption (local) -------------
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE1(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_1);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE2(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE3(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_3);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE4(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_4);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE5(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_5);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE6(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_6);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE7(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_7);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE8(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_8);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE9(Paseto.Builder builder) {
		encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_9);
	}

	// ------------- Decryption (local) -------------
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE1Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_1);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE2Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE3Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_3);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE4Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_4);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE5Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_5);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE6Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_6);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE7Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_7);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE8Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_8);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorE9Decrypt(Paseto.Builder builder) {
		decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_E_9);
	}

	// ------------- Sign (public) -------------
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorS1Sign(Paseto.Builder builder) {
		signTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_S_1, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorS2Sign(Paseto.Builder builder) {
		signTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_S_2, true);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorS3Sign(Paseto.Builder builder) {
		signTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_S_3, true);
	}

	// ------------- Verify (public) -------------
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorS1Verify(Paseto.Builder builder) {
		verifyTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_S_1);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorS2Verify(Paseto.Builder builder) {
		verifyTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_S_2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorS3Verify(Paseto.Builder builder) {
		verifyTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_S_3);
	}

	// -------------------------
	// Failure vectors (v4):
	// -------------------------

	// 4-F-1
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorF1EncryptFail(Paseto.Builder builder) {
		assertThrows(Exception.class, () ->
				encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_F_1)
		);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorF1DecryptFail(Paseto.Builder builder) {
		assertThrows(Exception.class, () ->
				decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_F_1)
		);
	}

	// 4-F-2
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorF2SignFail(Paseto.Builder builder) {
		assertThrows(AssertionFailedError.class, () ->
				signTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_F_2, true)
		);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorF2VerifyFail(Paseto.Builder builder) {
		assertThrows(SignatureVerificationException.class, () ->
				verifyTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_F_2)
		);
	}

	// 4-F-3
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorF3EncryptFail(Paseto.Builder builder) {
		assertThrows(KeyVersionException.class, () ->
				encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_F_3)
		);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorF3DecryptFail(Paseto.Builder builder) {
		assertThrows(KeyVersionException.class, () ->
				decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_F_3)
		);
	}

	// 4-F-4
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorF4EncryptFail(Paseto.Builder builder) {
		assertThrows(Exception.class, () ->
				encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_F_4)
		);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorF4DecryptFail(Paseto.Builder builder) {
		assertThrows(PasetoParseException.class, () ->
				decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_F_4)
		);
	}

	// 4-F-5 (v4.local bad base64 padding) — decrypt must fail
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorF5EncryptFail(Paseto.Builder builder) {
		assertThrows(Exception.class, () ->
				encryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_F_5)
		);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#pasetoV4Builders")
	public void v4_RfcVectorF5DecryptFail(Paseto.Builder builder) {
		assertThrows(Exception.class, () ->
				decryptTestVector(builder, RfcTestVectors.RFC_TEST_VECTOR_V4_F_5)
		);
	}

}
