package net.aholbrook.paseto.test;

import net.aholbrook.paseto.crypto.exception.ByteArrayLengthException;
import net.aholbrook.paseto.crypto.exception.ByteArrayRangeException;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;
import net.aholbrook.paseto.test.data.RfcTestVectors;
import net.aholbrook.paseto.test.utils.AssertUtils;
import net.aholbrook.paseto.test.utils.TestContext;
import org.junit.Assert;
import org.junit.Test;

public class V2CryptoProviderTest {
	// Define some empty arrays so our test code is cleaner.
	private final static byte[] BLAKE2B_OUT = new byte[V2CryptoProvider.BLAKE2B_BYTES_MIN];
	private final static byte[] BLAKE2B_IN = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
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

	private V2CryptoProvider v2CryptoProvider() {
		return TestContext.builders().v2CryptoProvider();
	}

	@Test
	public void crypto_v2_randomBytes() {
		byte[] r1 = v2CryptoProvider().randomBytes(24);
		byte[] r2 = v2CryptoProvider().randomBytes(24);
		AssertUtils.assertNotEquals(r1, r2);
	}

	@Test
	public void crypto_v2_nonce() {
		Assert.assertNotNull(v2CryptoProvider().getNonceGenerator());
		byte[] r1 = v2CryptoProvider().getNonceGenerator().generateNonce();
		byte[] r2 = v2CryptoProvider().getNonceGenerator().generateNonce();
		AssertUtils.assertNotEquals(r1, r2);
	}

	// Blake2b
	// Argument Testing
	@Test(expected = NullPointerException.class)
	public void crypto_v2_blake2b_nullOut() {
		v2CryptoProvider().blake2b(null, BLAKE2B_IN, BLAKE2B_KEY);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_blake2b_nullIn() {
		v2CryptoProvider().blake2b(BLAKE2B_OUT, null, BLAKE2B_KEY);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_blake2b_nullKey() {
		v2CryptoProvider().blake2b(BLAKE2B_OUT, BLAKE2B_IN, null);
	}

	@Test(expected = ByteArrayRangeException.class)
	public void crypto_v2_blake2b_outShort() {
		AssertUtils.assertByteArrayRangeException(() ->
						v2CryptoProvider().blake2b(new byte[V2CryptoProvider.BLAKE2B_BYTES_MIN - 1], BLAKE2B_IN,
								BLAKE2B_KEY),
				"out", V2CryptoProvider.BLAKE2B_BYTES_MIN - 1, V2CryptoProvider.BLAKE2B_BYTES_MIN,
				V2CryptoProvider.BLAKE2B_BYTES_MAX);

	}

	@Test(expected = ByteArrayRangeException.class)
	public void crypto_v2_blake2b_outLong() {
		AssertUtils.assertByteArrayRangeException(() ->
				v2CryptoProvider().blake2b(new byte[V2CryptoProvider.BLAKE2B_BYTES_MAX + 1], BLAKE2B_IN, BLAKE2B_KEY),
				"out", V2CryptoProvider.BLAKE2B_BYTES_MAX + 1, V2CryptoProvider.BLAKE2B_BYTES_MIN,
				V2CryptoProvider.BLAKE2B_BYTES_MAX);
	}

	@Test(expected = ByteArrayRangeException.class)
	public void crypto_v2_blake2b_keyShort() {
		AssertUtils.assertByteArrayRangeException(() ->
				v2CryptoProvider().blake2b(BLAKE2B_OUT, BLAKE2B_IN, new byte[V2CryptoProvider.BLAKE2B_KEYBYTES_MIN - 1]),
				"key", V2CryptoProvider.BLAKE2B_KEYBYTES_MIN - 1, V2CryptoProvider.BLAKE2B_KEYBYTES_MIN,
				V2CryptoProvider.BLAKE2B_KEYBYTES_MAX);
	}

	@Test(expected = ByteArrayRangeException.class)
	public void crypto_v2_blake2b_keyLong() {
		AssertUtils.assertByteArrayRangeException(() ->
				v2CryptoProvider().blake2b(BLAKE2B_OUT, BLAKE2B_IN, new byte[V2CryptoProvider.BLAKE2B_KEYBYTES_MAX + 1]),
				"key", V2CryptoProvider.BLAKE2B_KEYBYTES_MAX + 1, V2CryptoProvider.BLAKE2B_KEYBYTES_MIN,
				V2CryptoProvider.BLAKE2B_KEYBYTES_MAX);
	}

	// AeadXChaCha20Poly1305IetfEncrypt
	// Argument Testing
	@Test(expected = NullPointerException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_nullOut() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(null, XCHACHA20_POLY1305_IETF_IN,
				XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_nullIn() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT, null,
				XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_nullAd() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT, XCHACHA20_POLY1305_IETF_IN,
				null, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_nullNonce() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT, XCHACHA20_POLY1305_IETF_IN,
				XCHACHA20_POLY1305_IETF_AD, null, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_nullKey() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT, XCHACHA20_POLY1305_IETF_IN,
				XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, null);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortOut() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(
					new byte[XCHACHA20_POLY1305_IETF_OUT.length - 1],
					XCHACHA20_POLY1305_IETF_IN, XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE,
					XCHACHA20_POLY1305_IETF_KEY), "out", XCHACHA20_POLY1305_IETF_OUT.length - 1,
					XCHACHA20_POLY1305_IETF_OUT.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_longOut() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(
					new byte[XCHACHA20_POLY1305_IETF_OUT.length + 1],
					XCHACHA20_POLY1305_IETF_IN, XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE,
					XCHACHA20_POLY1305_IETF_KEY), "out", XCHACHA20_POLY1305_IETF_OUT.length + 1,
					XCHACHA20_POLY1305_IETF_OUT.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortIn() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT, new byte[0],
						XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY),
				"in", 0, 1, false);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortAd() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
						XCHACHA20_POLY1305_IETF_IN, new byte[0], XCHACHA20_POLY1305_IETF_NONCE,
						XCHACHA20_POLY1305_IETF_KEY),
				"ad", 0, 1, false);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortNonce() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
						XCHACHA20_POLY1305_IETF_IN, XCHACHA20_POLY1305_IETF_AD,
						new byte[XCHACHA20_POLY1305_IETF_NONCE.length - 1], XCHACHA20_POLY1305_IETF_KEY),
				"nonce", XCHACHA20_POLY1305_IETF_NONCE.length - 1, XCHACHA20_POLY1305_IETF_NONCE.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_longNonce() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
						XCHACHA20_POLY1305_IETF_IN, XCHACHA20_POLY1305_IETF_AD,
						new byte[XCHACHA20_POLY1305_IETF_NONCE.length + 1], XCHACHA20_POLY1305_IETF_KEY),
				"nonce", XCHACHA20_POLY1305_IETF_NONCE.length + 1, XCHACHA20_POLY1305_IETF_NONCE.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortKey() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
						XCHACHA20_POLY1305_IETF_IN, XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE,
						new byte[0]),
				"key", 0, 1, false);
	}

	// AeadXChaCha20Poly1305IetfDecrypt
	// Argument Testing
	@Test(expected = NullPointerException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_nullOut() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(null, XCHACHA20_POLY1305_IETF_IN_DECRYPT,
				XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_nullIn() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT, null,
				XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_nullAd() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
				XCHACHA20_POLY1305_IETF_IN_DECRYPT, null, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_nullNonce() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
				XCHACHA20_POLY1305_IETF_IN_DECRYPT, XCHACHA20_POLY1305_IETF_AD, null, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_nullKey() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
				XCHACHA20_POLY1305_IETF_IN_DECRYPT, XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, null);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_shortOut() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(
						new byte[XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length - 1], XCHACHA20_POLY1305_IETF_IN_DECRYPT,
						XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY),
				"out", XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length - 1, XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_longOut() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(
						new byte[XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length + 1], XCHACHA20_POLY1305_IETF_IN_DECRYPT,
						XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY),
				"out", XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length + 1, XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_shortIn() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT, new byte[0],
						XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY),
				"in", 0, 1, false);
	}

	// ed25519Sign
	// Argument Testing
	@Test(expected = NullPointerException.class)
	public void crypto_v2_ed25519Sign_nullSig() {
		v2CryptoProvider().ed25519Sign(null, ED25519S_M, ED25519S_SK);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_ed25519Sign_nullM() {
		v2CryptoProvider().ed25519Sign(ED25519S_SIG, null, ED25519S_SK);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_ed25519Sign_nullSk() {
		v2CryptoProvider().ed25519Sign(ED25519S_SIG, ED25519S_M, null);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Sign_shortSig() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519Sign(new byte[ED25519S_SIG.length - 1], ED25519S_M, ED25519S_SK),
				"sig", ED25519S_SIG.length - 1, ED25519S_SIG.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Sign_longSig() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519Sign(new byte[ED25519S_SIG.length + 1], ED25519S_M, ED25519S_SK),
				"sig", ED25519S_SIG.length + 1, ED25519S_SIG.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Sign_shortM() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519Sign(ED25519S_SIG, new byte[0], ED25519S_SK),
				"m", 0, 1, false);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Sign_shortSk() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519Sign(ED25519S_SIG, ED25519S_M, new byte[ED25519S_SK.length - 1]),
				"sk", ED25519S_SK.length - 1, ED25519S_SK.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Sign_longSk() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519Sign(ED25519S_SIG, ED25519S_M, new byte[ED25519S_SK.length + 1]),
				"sk", ED25519S_SK.length + 1, ED25519S_SK.length, true);
	}

	// ed25519Verify
	// Argument Testing
	@Test(expected = NullPointerException.class)
	public void crypto_v2_ed25519Verify_nullSig() {
		v2CryptoProvider().ed25519Verify(null, ED25519S_M, ED25519S_PK);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_ed25519Verify_nullM() {
		v2CryptoProvider().ed25519Verify(ED25519S_SIG, null, ED25519S_PK);
	}

	@Test(expected = NullPointerException.class)
	public void crypto_v2_ed25519Verify_nullPk() {
		v2CryptoProvider().ed25519Verify(ED25519S_SIG, ED25519S_M, null);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Verify_shortSig() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519Verify(new byte[ED25519S_SIG.length - 1], ED25519S_M, ED25519S_PK),
				"sig", ED25519S_SIG.length - 1, ED25519S_SIG.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Verify_longSig() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519Verify(new byte[ED25519S_SIG.length + 1], ED25519S_M, ED25519S_PK),
				"sig", ED25519S_SIG.length + 1, ED25519S_SIG.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Verify_shortM() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519Verify(ED25519S_SIG, new byte[0], ED25519S_PK),
				"m", 0, 1, false);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Verify_shortPk() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519Verify(ED25519S_SIG, ED25519S_M, new byte[ED25519S_PK.length - 1]),
				"pk", ED25519S_PK.length - 1, ED25519S_PK.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Verify_longPk() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519Verify(ED25519S_SIG, ED25519S_M, new byte[ED25519S_PK.length + 1]),
				"pk", ED25519S_PK.length + 1, ED25519S_PK.length, true);
	}

	// ed25519SkToPk
	// Argument Testing
	@Test(expected = NullPointerException.class)
	public void crypto_v2_ed25519PublicKey_nullSk() {
		v2CryptoProvider().ed25519SkToPk(null);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519PublicKey_shortSk() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519SkToPk(new byte[ED25519S_SK.length - 1]),
				"sk", ED25519S_SK.length - 1, ED25519S_SK.length, true);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519PublicKey_longSk() {
		AssertUtils.assertByteArrayLengthException(() ->
				v2CryptoProvider().ed25519SkToPk(new byte[ED25519S_SK.length + 1]),
				"sk", ED25519S_SK.length + 1, ED25519S_SK.length, true);
	}


	@Test
	public void crypto_v2_ed25519PublicKey() {
		byte[] pk = v2CryptoProvider().ed25519SkToPk(RfcTestVectors.RFC_TEST_SK);
		AssertUtils.assertEquals(RfcTestVectors.RFC_TEST_PK, pk);
	}
}
