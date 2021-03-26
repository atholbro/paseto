package net.aholbrook.paseto;

import net.aholbrook.paseto.crypto.exception.ByteArrayLengthException;
import net.aholbrook.paseto.crypto.exception.ByteArrayRangeException;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;
import net.aholbrook.paseto.data.RfcTestVectors;
import net.aholbrook.paseto.utils.AssertUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class V2CryptoProviderTest {
	// Define some empty arrays so our test code is cleaner.
	private final static byte[] BLAKE2B_OUT = new byte[V2CryptoProvider.BLAKE2B_BYTES_MIN];
	private final static byte[] BLAKE2B_IN = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
	private final static byte[] BLAKE2B_KEY = new byte[V2CryptoProvider.BLAKE2B_KEYBYTES_MIN];

	private final static byte[] XCHACHA20_POLY1305_IETF_IN = new byte[6];
	private final static byte[] XCHACHA20_POLY1305_IETF_OUT
			= new byte[V2CryptoProvider.XCHACHA20_POLY1305_IETF_ABYTES + XCHACHA20_POLY1305_IETF_IN.length];
	private final static byte[] XCHACHA20_POLY1305_IETF_IN_DECRYPT = XCHACHA20_POLY1305_IETF_OUT;
	private final static byte[] XCHACHA20_POLY1305_IETF_OUT_DECRYPT = XCHACHA20_POLY1305_IETF_IN;
	private final static byte[] XCHACHA20_POLY1305_IETF_AD = new byte[6];
	private final static byte[] XCHACHA20_POLY1305_IETF_NONCE
			= new byte[V2CryptoProvider.XCHACHA20_POLY1305_IETF_NPUBBYTES];
	private final static byte[] XCHACHA20_POLY1305_IETF_KEY = new byte[6];

	private final static byte[] ED25519S_SIG = new byte[V2CryptoProvider.ED25519_BYTES];
	private final static byte[] ED25519S_M = new byte[6];
	private final static byte[] ED25519S_SK = new byte[V2CryptoProvider.ED25519_SECRETKEYBYTES];
	private final static byte[] ED25519S_PK = new byte[V2CryptoProvider.ED25519_PUBLICKEYBYTES];

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_randomBytes(V2CryptoProvider v2CryptoProvider) {
		byte[] r1 = v2CryptoProvider.randomBytes(24);
		byte[] r2 = v2CryptoProvider.randomBytes(24);
		AssertUtils.assertNotEquals(r1, r2);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_nonce(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertNotNull(v2CryptoProvider.getNonceGenerator());
		byte[] r1 = v2CryptoProvider.getNonceGenerator().generateNonce();
		byte[] r2 = v2CryptoProvider.getNonceGenerator().generateNonce();
		AssertUtils.assertNotEquals(r1, r2);
	}

	// Blake2b
	// Argument Testing
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_blake2b_nullOut(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.blake2b(null, BLAKE2B_IN, BLAKE2B_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_blake2b_nullIn(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.blake2b(BLAKE2B_OUT, null, BLAKE2B_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_blake2b_nullKey(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.blake2b(BLAKE2B_OUT, BLAKE2B_IN, null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_blake2b_outShort(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayRangeException.class,
				() -> AssertUtils.assertByteArrayRangeException(
						() -> v2CryptoProvider.blake2b(new byte[V2CryptoProvider.BLAKE2B_BYTES_MIN - 1],
								BLAKE2B_IN,
								BLAKE2B_KEY),
						"out", V2CryptoProvider.BLAKE2B_BYTES_MIN - 1,
						V2CryptoProvider.BLAKE2B_BYTES_MIN,
						V2CryptoProvider.BLAKE2B_BYTES_MAX));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_blake2b_outLong(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayRangeException.class,
				() -> AssertUtils.assertByteArrayRangeException(
						() -> v2CryptoProvider.blake2b(new byte[V2CryptoProvider.BLAKE2B_BYTES_MAX + 1],
								BLAKE2B_IN,
								BLAKE2B_KEY),
						"out",
						V2CryptoProvider.BLAKE2B_BYTES_MAX + 1,
						V2CryptoProvider.BLAKE2B_BYTES_MIN,
						V2CryptoProvider.BLAKE2B_BYTES_MAX));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_blake2b_keyShort(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayRangeException.class,
				() -> AssertUtils.assertByteArrayRangeException(
						() -> v2CryptoProvider.blake2b(BLAKE2B_OUT,
								BLAKE2B_IN,
								new byte[V2CryptoProvider.BLAKE2B_KEYBYTES_MIN - 1]),
						"key",
						V2CryptoProvider.BLAKE2B_KEYBYTES_MIN - 1,
						V2CryptoProvider.BLAKE2B_KEYBYTES_MIN,
						V2CryptoProvider.BLAKE2B_KEYBYTES_MAX));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_blake2b_keyLong(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayRangeException.class,
				() -> AssertUtils.assertByteArrayRangeException(
						() -> v2CryptoProvider.blake2b(BLAKE2B_OUT, BLAKE2B_IN,
								new byte[V2CryptoProvider.BLAKE2B_KEYBYTES_MAX + 1]),
						"key",
						V2CryptoProvider.BLAKE2B_KEYBYTES_MAX + 1,
						V2CryptoProvider.BLAKE2B_KEYBYTES_MIN,
						V2CryptoProvider.BLAKE2B_KEYBYTES_MAX));
	}

	// Argument Testing
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_nullOut(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(null,
						XCHACHA20_POLY1305_IETF_IN,
						XCHACHA20_POLY1305_IETF_AD,
						XCHACHA20_POLY1305_IETF_NONCE,
						XCHACHA20_POLY1305_IETF_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_nullIn(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
						null,
						XCHACHA20_POLY1305_IETF_AD,
						XCHACHA20_POLY1305_IETF_NONCE,
						XCHACHA20_POLY1305_IETF_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_nullAd(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
						XCHACHA20_POLY1305_IETF_IN,
						null,
						XCHACHA20_POLY1305_IETF_NONCE,
						XCHACHA20_POLY1305_IETF_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_nullNonce(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
						XCHACHA20_POLY1305_IETF_IN,
						XCHACHA20_POLY1305_IETF_AD,
						null,
						XCHACHA20_POLY1305_IETF_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_nullKey(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
						XCHACHA20_POLY1305_IETF_IN,
						XCHACHA20_POLY1305_IETF_AD,
						XCHACHA20_POLY1305_IETF_NONCE,
						null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortOut(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(
								new byte[XCHACHA20_POLY1305_IETF_OUT.length - 1],
								XCHACHA20_POLY1305_IETF_IN,
								XCHACHA20_POLY1305_IETF_AD,
								XCHACHA20_POLY1305_IETF_NONCE,
								XCHACHA20_POLY1305_IETF_KEY),
						"out",
						XCHACHA20_POLY1305_IETF_OUT.length - 1,
						XCHACHA20_POLY1305_IETF_OUT.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_longOut(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(
								new byte[XCHACHA20_POLY1305_IETF_OUT.length + 1],
								XCHACHA20_POLY1305_IETF_IN,
								XCHACHA20_POLY1305_IETF_AD,
								XCHACHA20_POLY1305_IETF_NONCE,
								XCHACHA20_POLY1305_IETF_KEY),
						"out",
						XCHACHA20_POLY1305_IETF_OUT.length + 1,
						XCHACHA20_POLY1305_IETF_OUT.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortIn(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
								new byte[0],
								XCHACHA20_POLY1305_IETF_AD,
								XCHACHA20_POLY1305_IETF_NONCE,
								XCHACHA20_POLY1305_IETF_KEY),
						"in",
						0,
						1,
						false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortAd(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
								XCHACHA20_POLY1305_IETF_IN,
								new byte[0],
								XCHACHA20_POLY1305_IETF_NONCE,
								XCHACHA20_POLY1305_IETF_KEY),
						"ad",
						0,
						1,
						false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortNonce(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
								XCHACHA20_POLY1305_IETF_IN,
								XCHACHA20_POLY1305_IETF_AD,
								new byte[XCHACHA20_POLY1305_IETF_NONCE.length - 1],
								XCHACHA20_POLY1305_IETF_KEY),
						"nonce",
						XCHACHA20_POLY1305_IETF_NONCE.length - 1,
						XCHACHA20_POLY1305_IETF_NONCE.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_longNonce(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
								XCHACHA20_POLY1305_IETF_IN,
								XCHACHA20_POLY1305_IETF_AD,
								new byte[XCHACHA20_POLY1305_IETF_NONCE.length + 1],
								XCHACHA20_POLY1305_IETF_KEY),
						"nonce",
						XCHACHA20_POLY1305_IETF_NONCE.length + 1,
						XCHACHA20_POLY1305_IETF_NONCE.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortKey(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
								XCHACHA20_POLY1305_IETF_IN,
								XCHACHA20_POLY1305_IETF_AD,
								XCHACHA20_POLY1305_IETF_NONCE,
								new byte[0]),
						"key",
						0,
						1,
						false));
	}

	// Argument Testing
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_nullOut(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfDecrypt(null,
						XCHACHA20_POLY1305_IETF_IN_DECRYPT,
						XCHACHA20_POLY1305_IETF_AD,
						XCHACHA20_POLY1305_IETF_NONCE,
						XCHACHA20_POLY1305_IETF_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_nullIn(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
						null,
						XCHACHA20_POLY1305_IETF_AD,
						XCHACHA20_POLY1305_IETF_NONCE,
						XCHACHA20_POLY1305_IETF_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_nullAd(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
						XCHACHA20_POLY1305_IETF_IN_DECRYPT,
						null,
						XCHACHA20_POLY1305_IETF_NONCE,
						XCHACHA20_POLY1305_IETF_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_nullNonce(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
						XCHACHA20_POLY1305_IETF_IN_DECRYPT,
						XCHACHA20_POLY1305_IETF_AD,
						null,
						XCHACHA20_POLY1305_IETF_KEY));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_nullKey(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
						XCHACHA20_POLY1305_IETF_IN_DECRYPT,
						XCHACHA20_POLY1305_IETF_AD,
						XCHACHA20_POLY1305_IETF_NONCE,
						null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_shortOut(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfDecrypt(
								new byte[XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length - 1],
								XCHACHA20_POLY1305_IETF_IN_DECRYPT,
								XCHACHA20_POLY1305_IETF_AD,
								XCHACHA20_POLY1305_IETF_NONCE,
								XCHACHA20_POLY1305_IETF_KEY),
						"out",
						XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length - 1,
						XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_longOut(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.aeadXChaCha20Poly1305IetfDecrypt(
								new byte[XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length + 1],
								XCHACHA20_POLY1305_IETF_IN_DECRYPT,
								XCHACHA20_POLY1305_IETF_AD,
								XCHACHA20_POLY1305_IETF_NONCE,
								XCHACHA20_POLY1305_IETF_KEY),
						"out",
						XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length + 1,
						XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_shortIn(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(() ->
								v2CryptoProvider.aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
										new byte[0],
										XCHACHA20_POLY1305_IETF_AD,
										XCHACHA20_POLY1305_IETF_NONCE,
										XCHACHA20_POLY1305_IETF_KEY),
						"in",
						0,
						1,
						false));
	}

	// ed25519Sign
	// Argument Testing
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Sign_nullSig(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.ed25519Sign(null, ED25519S_M, ED25519S_SK));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Sign_nullM(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.ed25519Sign(ED25519S_SIG, null, ED25519S_SK));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Sign_nullSk(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.ed25519Sign(ED25519S_SIG, ED25519S_M, null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Sign_shortSig(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519Sign(new byte[ED25519S_SIG.length - 1],
								ED25519S_M,
								ED25519S_SK),
						"sig",
						ED25519S_SIG.length - 1,
						ED25519S_SIG.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Sign_longSig(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519Sign(new byte[ED25519S_SIG.length + 1],
								ED25519S_M,
								ED25519S_SK),
						"sig",
						ED25519S_SIG.length + 1,
						ED25519S_SIG.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Sign_shortM(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519Sign(ED25519S_SIG,
								new byte[0],
								ED25519S_SK),
						"m",
						0,
						1,
						false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Sign_shortSk(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519Sign(ED25519S_SIG,
								ED25519S_M,
								new byte[ED25519S_SK.length - 1]),
						"sk",
						ED25519S_SK.length - 1,
						ED25519S_SK.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Sign_longSk(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519Sign(ED25519S_SIG,
								ED25519S_M,
								new byte[ED25519S_SK.length + 1]),
						"sk",
						ED25519S_SK.length + 1,
						ED25519S_SK.length,
						true));
	}

	// ed25519Verify
	// Argument Testing
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Verify_nullSig(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.ed25519Verify(null, ED25519S_M, ED25519S_PK));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Verify_nullM(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.ed25519Verify(ED25519S_SIG, null, ED25519S_PK));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Verify_nullPk(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.ed25519Verify(ED25519S_SIG, ED25519S_M, null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Verify_shortSig(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519Verify(new byte[ED25519S_SIG.length - 1],
								ED25519S_M,
								ED25519S_PK),
						"sig",
						ED25519S_SIG.length - 1,
						ED25519S_SIG.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Verify_longSig(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519Verify(new byte[ED25519S_SIG.length + 1],
								ED25519S_M,
								ED25519S_PK),
						"sig",
						ED25519S_SIG.length + 1,
						ED25519S_SIG.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Verify_shortM(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519Verify(ED25519S_SIG,
								new byte[0],
								ED25519S_PK),
						"m",
						0,
						1,
						false));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Verify_shortPk(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519Verify(ED25519S_SIG,
								ED25519S_M,
								new byte[ED25519S_PK.length - 1]),
						"pk",
						ED25519S_PK.length - 1,
						ED25519S_PK.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519Verify_longPk(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519Verify(ED25519S_SIG,
								ED25519S_M,
								new byte[ED25519S_PK.length + 1]),
						"pk",
						ED25519S_PK.length + 1,
						ED25519S_PK.length,
						true));
	}

	// ed25519SkToPk
	// Argument Testing
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519PublicKey_nullSk(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(NullPointerException.class,
				() -> v2CryptoProvider.ed25519SkToPk(null));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519PublicKey_shortSk(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519SkToPk(new byte[ED25519S_SK.length - 1]),
						"sk",
						ED25519S_SK.length - 1,
						ED25519S_SK.length,
						true));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519PublicKey_longSk(V2CryptoProvider v2CryptoProvider) {
		Assertions.assertThrows(ByteArrayLengthException.class,
				() -> AssertUtils.assertByteArrayLengthException(
						() -> v2CryptoProvider.ed25519SkToPk(new byte[ED25519S_SK.length + 1]),
						"sk",
						ED25519S_SK.length + 1,
						ED25519S_SK.length,
						true));
	}


	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#v2CryptoProviders")
	public void crypto_v2_ed25519PublicKey(V2CryptoProvider v2CryptoProvider) {
		byte[] pk = v2CryptoProvider.ed25519SkToPk(RfcTestVectors.RFC_TEST_SK);
		AssertUtils.assertEquals(RfcTestVectors.RFC_TEST_PK, pk);
	}
}
