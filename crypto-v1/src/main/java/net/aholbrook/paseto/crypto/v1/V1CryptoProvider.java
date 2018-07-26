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

package net.aholbrook.paseto.crypto.v1;

import net.aholbrook.paseto.crypto.NonceGenerator;
import net.aholbrook.paseto.crypto.Tuple;
import net.aholbrook.paseto.crypto.exception.ByteArrayLengthException;

import java.math.BigInteger;

public abstract class V1CryptoProvider implements NonceGenerator {
	public final static int NONCE_SIZE = 32;
	public final static int HKDF_SALT_LEN = 16;
	public final static int SHA384_OUT_LEN = 48;
	public final static int RSA_SIGNATURE_LEN = 256;

	protected final static int HKDF_LEN = 32;
	protected final static int RSA_KEY_SIZE = 2048;
	protected final static BigInteger E = BigInteger.valueOf(65537L);

	// RNG
	abstract public byte[] randomBytes(int size);

	// Nonce
	public NonceGenerator getNonceGenerator() {
		return this;
	}

	@Override
	public byte[] generateNonce() {
		return randomBytes(NONCE_SIZE);
	}

	// HKDF
	abstract public byte[] hkdfExtractAndExpand(byte[] salt, byte[] inputKeyingMaterial, byte[] info);

	// Hmac SHA 384
	abstract public byte[] hmacSha384(byte[] m, byte[] key);

	// AES-256-CTR
	abstract public byte[] aes256Ctr(byte[] m, byte[] key, byte[] iv);
	abstract public byte[] aes256CtrDecrypt(byte[] c, byte[] key, byte[] iv);

	// RSA Signatures
	abstract public byte[] rsaSign(byte[] m, byte[] privateKey);
	abstract public boolean rsaVerify(byte[] m, byte[] sig, byte[] publicKey);
	abstract public Tuple<byte[], byte[]> rsaGenerate();

	// Validation
	protected final void validateHkdfExtractAndExpand(byte[] salt, byte[] inputKeyingMaterial, byte[] info) {
		if (salt == null) { throw new NullPointerException("salt"); }
		if (inputKeyingMaterial == null) { throw new NullPointerException("inputKeyingMaterial"); }
		if (info == null) { throw new NullPointerException("info"); }

		if (salt.length != HKDF_SALT_LEN) {
			throw new ByteArrayLengthException("salt", salt.length, HKDF_SALT_LEN, true);
		}
		if (inputKeyingMaterial.length < 1) {
			throw new ByteArrayLengthException("inputKeyingMaterial", inputKeyingMaterial.length, 1, false);
		}
		if (info.length < 1) {
			throw new ByteArrayLengthException("info", info.length, 1, false);
		}
	}

	protected final void validateHmacSha384(byte[] m, byte[] key) {
		if (m == null) { throw new NullPointerException("m"); }
		if (key == null) { throw new NullPointerException("key"); }

		if (m.length < 1) { throw new ByteArrayLengthException("m", m.length, 1, false); }
		if (key.length < 1) { throw new ByteArrayLengthException("key", key.length, 1, false); }
	}

	private final void validateAes256Ctr(byte[] key, byte[] iv) {
		if (key == null) { throw new NullPointerException("key"); }
		if (iv == null) { throw new NullPointerException("iv"); }

		if (key.length < 1) { throw new ByteArrayLengthException("key", key.length, 1, false); }
		if (iv.length < 1) { throw new ByteArrayLengthException("iv", iv.length, 8, false); }
	}

	protected final void validateAes256CtrEncrypt(byte[] m, byte[] key, byte[] iv) {
		validateAes256Ctr(key, iv);
		if (m == null) { throw new NullPointerException("m"); }
		if (m.length < 1) { throw new ByteArrayLengthException("m", m.length, 1, false); }
	}

	protected final void validateAes256CtrDecrypt(byte[] c, byte[] key, byte[] iv) {
		validateAes256Ctr(key, iv);
		if (c == null) { throw new NullPointerException("c"); }
		if (c.length < 1) { throw new ByteArrayLengthException("c", c.length, 1, false); }
	}

	protected final void validateRsaSign(byte[] m, byte[] privateKey) {
		if (m == null) { throw new NullPointerException("m"); }
		if (privateKey == null) { throw new NullPointerException("privateKey"); }

		if (m.length < 1) { throw new ByteArrayLengthException("m", m.length, 1, false); }
		if (privateKey.length < 1) { throw new ByteArrayLengthException("privateKey", privateKey.length, 1, false); }
	}

	protected final void validateRsaVerify(byte[] m, byte[] sig, byte[] publicKey) {
		if (m == null) { throw new NullPointerException("m"); }
		if (sig == null) { throw new NullPointerException("sig"); }
		if (publicKey == null) { throw new NullPointerException("publicKey"); }

		if (m.length < 1) { throw new ByteArrayLengthException("m", m.length, 1, false); }
		if (sig.length != RSA_SIGNATURE_LEN) {
			throw new ByteArrayLengthException("sig", sig.length, RSA_SIGNATURE_LEN, true);
		}
		if (publicKey.length < 1) { throw new ByteArrayLengthException("publicKey", publicKey.length, 1, false); }
	}
}
