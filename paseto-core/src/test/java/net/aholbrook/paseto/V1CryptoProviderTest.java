package net.aholbrook.paseto;

import net.aholbrook.paseto.crypto.KeyPair;
import net.aholbrook.paseto.crypto.exception.ByteArrayLengthException;
import net.aholbrook.paseto.crypto.exception.CryptoProviderException;
import net.aholbrook.paseto.crypto.v1.V1CryptoProvider;
import net.aholbrook.paseto.data.RfcTestVectors;
import net.aholbrook.paseto.util.StringUtils;
import net.aholbrook.paseto.utils.AssertUtils;
import net.aholbrook.paseto.utils.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class V1CryptoProviderTest {
	private static final byte[] HKDF_SALT = {
			0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10
	};
	private static final byte[] RSA_FAKE_SIGNATURE = new byte[V1CryptoProvider.RSA_SIGNATURE_LEN];

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_randomBytes(V1CryptoProvider v1CryptoProvider) {
		byte[] r1 = v1CryptoProvider.randomBytes(24);
		byte[] r2 = v1CryptoProvider.randomBytes(24);
		AssertUtils.assertNotEquals(r1, r2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_nonce(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertNotNull(v1CryptoProvider.getNonceGenerator());
		byte[] r1 = v1CryptoProvider.getNonceGenerator().generateNonce();
		byte[] r2 = v1CryptoProvider.getNonceGenerator().generateNonce();
		AssertUtils.assertNotEquals(r1, r2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hkdfExtractAndExpand_nullSalt(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> {
			// HmacSha384TestVectors used just to provide some data, we're not testing the result but only the input
			// validation.
			v1CryptoProvider.hkdfExtractAndExpand(null, HmacSha384TestVectors.VECTOR_1_KEY,
					HmacSha384TestVectors.VECTOR_1_DATA);
		});
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hkdfExtractAndExpand_shortSalt(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.hkdfExtractAndExpand(
								new byte[]{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF},
								HmacSha384TestVectors.VECTOR_1_KEY, HmacSha384TestVectors.VECTOR_1_DATA),
				"salt", 15, V1CryptoProvider.HKDF_SALT_LEN, true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hkdfExtractAndExpand_longSalt(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.hkdfExtractAndExpand(
								new byte[]{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x11},
								HmacSha384TestVectors.VECTOR_1_KEY, HmacSha384TestVectors.VECTOR_1_DATA),
				"salt", 17, V1CryptoProvider.HKDF_SALT_LEN, true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hkdfExtractAndExpand_nullIkm(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.hkdfExtractAndExpand(HKDF_SALT, null,
				HmacSha384TestVectors.VECTOR_1_DATA));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hkdfExtractAndExpand_invalidIkm(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.hkdfExtractAndExpand(HKDF_SALT, new byte[]{}, HmacSha384TestVectors.VECTOR_1_DATA),
				"inputKeyingMaterial", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hkdfExtractAndExpand_nullInfo(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.hkdfExtractAndExpand(HKDF_SALT, HmacSha384TestVectors.VECTOR_1_KEY,
				null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hkdfExtractAndExpand_invalidInfo(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.hkdfExtractAndExpand(HKDF_SALT, HmacSha384TestVectors.VECTOR_1_KEY, new byte[]{}),
				"info", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hmacSha384(V1CryptoProvider v1CryptoProvider) {
		byte[] hmac = v1CryptoProvider.hmacSha384(HmacSha384TestVectors.VECTOR_1_DATA,
				HmacSha384TestVectors.VECTOR_1_KEY);
		AssertUtils.assertEquals(HmacSha384TestVectors.VECTOR_1_HMAC, hmac);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hmacSha384_nullMessage(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.hmacSha384(null, HmacSha384TestVectors.VECTOR_1_DATA));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hmacSha384_emptyMessage(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.hmacSha384(new byte[]{}, HmacSha384TestVectors.VECTOR_1_DATA),
				"m", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hmacSha384_nullKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.hmacSha384(HmacSha384TestVectors.VECTOR_1_DATA, null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_hmacSha384_emptyKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.hmacSha384(HmacSha384TestVectors.VECTOR_1_DATA, new byte[]{}),
				"key", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrEncrypt(V1CryptoProvider v1CryptoProvider) {
		byte[] c = v1CryptoProvider.aes256CtrEncrypt(Aes256CtrTestVectors.PLAINTEXT, Aes256CtrTestVectors.KEY,
				Aes256CtrTestVectors.IV);

		AssertUtils.assertEquals(Aes256CtrTestVectors.CIPHERTEXT, c);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrEncrypt_nullMessage(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.aes256CtrEncrypt(null, Aes256CtrTestVectors.KEY, Aes256CtrTestVectors.IV));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrEncrypt_invalidMessage(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.aes256CtrEncrypt(new byte[]{}, Aes256CtrTestVectors.KEY, Aes256CtrTestVectors.IV),
				"m", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrEncrypt_nullKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.aes256CtrEncrypt(Aes256CtrTestVectors.PLAINTEXT, null, Aes256CtrTestVectors.IV));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrEncrypt_invalidKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.aes256CtrEncrypt(Aes256CtrTestVectors.PLAINTEXT, new byte[]{}, Aes256CtrTestVectors.IV),
				"key", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrEncrypt_nullIv(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.aes256CtrEncrypt(Aes256CtrTestVectors.PLAINTEXT, Aes256CtrTestVectors.KEY, null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrEncrypt_invalidIv(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.aes256CtrEncrypt(Aes256CtrTestVectors.PLAINTEXT, Aes256CtrTestVectors.KEY,
								new byte[]{}),
				"iv", 0, 8, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrDecrypt(V1CryptoProvider v1CryptoProvider) {
		byte[] m = v1CryptoProvider.aes256CtrDecrypt(Aes256CtrTestVectors.CIPHERTEXT, Aes256CtrTestVectors.KEY,
				Aes256CtrTestVectors.IV);

		AssertUtils.assertEquals(Aes256CtrTestVectors.PLAINTEXT, m);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrDecrypt_nullMessage(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.aes256CtrDecrypt(null, Aes256CtrTestVectors.KEY, Aes256CtrTestVectors.IV));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrDecrypt_invalidMessage(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.aes256CtrDecrypt(new byte[]{}, Aes256CtrTestVectors.KEY, Aes256CtrTestVectors.IV),
				"c", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrDecrypt_nullKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.aes256CtrDecrypt(Aes256CtrTestVectors.PLAINTEXT, null, Aes256CtrTestVectors.IV));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrDecrypt_invalidKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.aes256CtrDecrypt(Aes256CtrTestVectors.PLAINTEXT, new byte[]{}, Aes256CtrTestVectors.IV),
				"key", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrDecrypt_nullIv(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.aes256CtrDecrypt(Aes256CtrTestVectors.PLAINTEXT, Aes256CtrTestVectors.KEY, null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_aes256CtrDecrypt_invalidIv(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.aes256CtrDecrypt(Aes256CtrTestVectors.PLAINTEXT, Aes256CtrTestVectors.KEY,
								new byte[]{}),
				"iv", 0, 8, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaSign_badKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(CryptoProviderException.class, () -> v1CryptoProvider.rsaSign(StringUtils.getBytesUtf8("test"), new byte[]{0x01}));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaSign_nullMessage(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.rsaSign(null, RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaSign_invalidMessage(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.rsaSign(new byte[]{}, RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY),
				"m", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaSign_nullPrivateKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.rsaSign(StringUtils.getBytesUtf8("test"), null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaSign_invalidPrivateKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.rsaSign(StringUtils.getBytesUtf8("test"), new byte[]{}),
				"privateKey", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaVerify_badKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(CryptoProviderException.class, () -> v1CryptoProvider.rsaVerify(StringUtils.getBytesUtf8("test"), RSA_FAKE_SIGNATURE, new byte[]{0x01}));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaVerify_nullMessage(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.rsaVerify(null, RSA_FAKE_SIGNATURE, RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaVerify_invalidMessage(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.rsaVerify(new byte[]{}, RSA_FAKE_SIGNATURE,
								RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY),
				"m", 0, 1, false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaVerify_nullSignature(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.rsaVerify(StringUtils.getBytesUtf8("test"), null, RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaVerify_shortSignature(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.rsaVerify(StringUtils.getBytesUtf8("test"),
								new byte[V1CryptoProvider.RSA_SIGNATURE_LEN - 1],
								RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY),
				"sig", V1CryptoProvider.RSA_SIGNATURE_LEN - 1, V1CryptoProvider.RSA_SIGNATURE_LEN, true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaVerify_longSignature(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.rsaVerify(StringUtils.getBytesUtf8("test"),
								new byte[V1CryptoProvider.RSA_SIGNATURE_LEN + 1],
								RfcTestVectors.RFC_TEST_RSA_PRIVATE_KEY),
				"sig", V1CryptoProvider.RSA_SIGNATURE_LEN + 1, V1CryptoProvider.RSA_SIGNATURE_LEN, true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaVerify_nullPublicKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class, () -> v1CryptoProvider.rsaVerify(StringUtils.getBytesUtf8("test"), RSA_FAKE_SIGNATURE, null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_rsaVerify_invalidPublicKey(V1CryptoProvider v1CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class, () -> AssertUtils.assertByteArrayLengthException(() ->
						v1CryptoProvider.rsaVerify(StringUtils.getBytesUtf8("test"), RSA_FAKE_SIGNATURE,
								new byte[]{}),
				"publicKey", 0, 1, false));
	}

	// Generate a key pair, sign a message, then verify the signature
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v1CryptoProviders")
	public void crypto_v1_generateKeyPair(V1CryptoProvider v1CryptoProvider) {
		byte[] message = StringUtils.getBytesUtf8("test message");
		KeyPair keyPair = v1CryptoProvider.rsaGenerate();
		byte[] sig = v1CryptoProvider.rsaSign(message, keyPair.getSecretKey());
		v1CryptoProvider.rsaVerify(message, sig, keyPair.getPublicKey());
	}

	// https://www.ietf.org/rfc/rfc4868.txt
	private static class HmacSha384TestVectors {
		public static final byte[] VECTOR_1_KEY = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
				+ "0b0b0b0b");
		public static final byte[] VECTOR_1_DATA = Hex.decode("4869205468657265");
		public static final byte[] VECTOR_1_HMAC = Hex.decode("afd03944d84895626b0825f4ab46907f"
				+ "15f9dadbe4101ec682aa034c7cebc59c"
				+ "faea9ea9076ede7f4af152e8b2fa9cb6");
	}

	// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
	private static class Aes256CtrTestVectors {
		public static final byte[] KEY = Hex.decode(
				"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
		public static final byte[] IV = Hex.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
		public static final byte[] PLAINTEXT = Hex.decode("6bc1bee22e409f96e93d7e117393172a");
		public static final byte[] CIPHERTEXT = Hex.decode("601ec313775789a5b7a7f504bbf3d228");

	}
}
