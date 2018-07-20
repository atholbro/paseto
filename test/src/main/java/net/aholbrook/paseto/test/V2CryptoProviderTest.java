package net.aholbrook.paseto.test;

import net.aholbrook.paseto.crypto.exception.ByteArrayLengthException;
import net.aholbrook.paseto.crypto.exception.ByteArrayRangeException;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;
import net.aholbrook.paseto.test.data.RfcTestVectors;
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
		v2CryptoProvider().blake2b(new byte[V2CryptoProvider.BLAKE2B_BYTES_MIN - 1], BLAKE2B_IN, BLAKE2B_KEY);
	}

	@Test(expected = ByteArrayRangeException.class)
	public void crypto_v2_blake2b_outLong() {
		v2CryptoProvider().blake2b(new byte[V2CryptoProvider.BLAKE2B_BYTES_MAX + 1], BLAKE2B_IN, BLAKE2B_KEY);
	}

	@Test(expected = ByteArrayRangeException.class)
	public void crypto_v2_blake2b_keyShort() {
		v2CryptoProvider().blake2b(BLAKE2B_OUT, BLAKE2B_IN, new byte[V2CryptoProvider.BLAKE2B_KEYBYTES_MIN - 1]);
	}

	@Test(expected = ByteArrayRangeException.class)
	public void crypto_v2_blake2b_keyLong() {
		byte[] key = new byte[V2CryptoProvider.BLAKE2B_KEYBYTES_MAX + 1];
		v2CryptoProvider().blake2b(BLAKE2B_OUT, BLAKE2B_IN, new byte[V2CryptoProvider.BLAKE2B_KEYBYTES_MAX + 1]);
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
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(
				new byte[XCHACHA20_POLY1305_IETF_OUT.length - 1],
				XCHACHA20_POLY1305_IETF_IN, XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE,
				XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_longOut() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(
				new byte[XCHACHA20_POLY1305_IETF_OUT.length + 1],
				XCHACHA20_POLY1305_IETF_IN, XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE,
				XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortIn() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT, new byte[0],
				XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortAd() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT, XCHACHA20_POLY1305_IETF_IN,
				new byte[0], XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortNonce() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
				XCHACHA20_POLY1305_IETF_IN, XCHACHA20_POLY1305_IETF_AD,
				new byte[XCHACHA20_POLY1305_IETF_NONCE.length - 1], XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_longNonce() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT,
				XCHACHA20_POLY1305_IETF_IN, XCHACHA20_POLY1305_IETF_AD,
				new byte[XCHACHA20_POLY1305_IETF_NONCE.length + 1], XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfEncrypt_shortKey() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfEncrypt(XCHACHA20_POLY1305_IETF_OUT, XCHACHA20_POLY1305_IETF_IN,
				XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, new byte[0]);
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
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(
				new byte[XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length - 1],
				XCHACHA20_POLY1305_IETF_IN_DECRYPT, XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE,
				XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_longOut() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(
				new byte[XCHACHA20_POLY1305_IETF_OUT_DECRYPT.length + 1],
				XCHACHA20_POLY1305_IETF_IN_DECRYPT, XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE,
				XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_shortIn() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT, new byte[0],
				XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_shortAd() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
				XCHACHA20_POLY1305_IETF_IN_DECRYPT, new byte[0], XCHACHA20_POLY1305_IETF_NONCE, XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_shortNonce() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
				XCHACHA20_POLY1305_IETF_IN_DECRYPT, XCHACHA20_POLY1305_IETF_AD,
				new byte[XCHACHA20_POLY1305_IETF_NONCE.length - 1], XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_longNonce() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
				XCHACHA20_POLY1305_IETF_IN_DECRYPT, XCHACHA20_POLY1305_IETF_AD,
				new byte[XCHACHA20_POLY1305_IETF_NONCE.length + 1], XCHACHA20_POLY1305_IETF_KEY);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_aeadXChaCha20Poly1305IetfDecrypt_shortKey() {
		v2CryptoProvider().aeadXChaCha20Poly1305IetfDecrypt(XCHACHA20_POLY1305_IETF_OUT_DECRYPT,
				XCHACHA20_POLY1305_IETF_IN_DECRYPT, XCHACHA20_POLY1305_IETF_AD, XCHACHA20_POLY1305_IETF_NONCE, new byte[0]);
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
		v2CryptoProvider().ed25519Sign(new byte[ED25519S_SIG.length - 1], ED25519S_M, ED25519S_SK);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Sign_longSig() {
		v2CryptoProvider().ed25519Sign(new byte[ED25519S_SIG.length + 1], ED25519S_M, ED25519S_SK);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Sign_shortM() {
		v2CryptoProvider().ed25519Sign(ED25519S_SIG, new byte[0], ED25519S_SK);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Sign_shortSk() {
		v2CryptoProvider().ed25519Sign(ED25519S_SIG, ED25519S_M, new byte[ED25519S_SK.length - 1]);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Sign_longSk() {
		v2CryptoProvider().ed25519Sign(ED25519S_SIG, ED25519S_M, new byte[ED25519S_SK.length + 1]);
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
		v2CryptoProvider().ed25519Verify(new byte[ED25519S_SIG.length - 1], ED25519S_M, ED25519S_PK);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Verify_longSig() {
		v2CryptoProvider().ed25519Verify(new byte[ED25519S_SIG.length + 1], ED25519S_M, ED25519S_PK);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Verify_shortM() {
		v2CryptoProvider().ed25519Verify(ED25519S_SIG, new byte[0], ED25519S_PK);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Verify_shortPk() {
		v2CryptoProvider().ed25519Verify(ED25519S_SIG, ED25519S_M, new byte[ED25519S_PK.length - 1]);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519Verify_longPk() {
		v2CryptoProvider().ed25519Verify(ED25519S_SIG, ED25519S_M, new byte[ED25519S_PK.length + 1]);
	}

	// ed25519PublicKey
	// Argument Testing
	@Test(expected = NullPointerException.class)
	public void crypto_v2_ed25519PublicKey_nullSk() {
		v2CryptoProvider().ed25519PublicKey(null);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519PublicKey_shortSk() {
		v2CryptoProvider().ed25519PublicKey(new byte[ED25519S_SK.length - 1]);
	}

	@Test(expected = ByteArrayLengthException.class)
	public void crypto_v2_ed25519PublicKey_longSk() {
		v2CryptoProvider().ed25519PublicKey(new byte[ED25519S_SK.length + 1]);
	}


	@Test
	public void crypto_v2_ed25519PublicKey() {
		byte[] pk = v2CryptoProvider().ed25519PublicKey(RfcTestVectors.rfcTestV2SecretKey());
		AssertUtils.assertEquals(RfcTestVectors.rfcTestV2PublicKey(), pk);
	}
}
