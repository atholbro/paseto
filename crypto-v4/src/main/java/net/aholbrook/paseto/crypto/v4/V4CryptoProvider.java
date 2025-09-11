package net.aholbrook.paseto.crypto.v4;

import net.aholbrook.paseto.crypto.NonceGenerator;
import net.aholbrook.paseto.crypto.Pair;
import net.aholbrook.paseto.crypto.exception.ByteArrayLengthException;
import net.aholbrook.paseto.crypto.exception.ByteArrayRangeException;

public abstract class V4CryptoProvider implements NonceGenerator {
	protected final static int V4_NONCE_BYTES = 32;

	private final static int BLAKE2B_BYTES_MIN = 16;
	private final static int BLAKE2B_BYTES_MAX = 64;
	private final static int BLAKE2B_KEYBYTES_MIN = 16;
	private final static int BLAKE2B_KEYBYTES_MAX = 64;

	private final static int XCHACHA20_XOR_KEY_BYTES = 32; // key length
	private final static int XCHACHA20_XOR_NONCE_BYTES = 24; // nonce length

	private final static int ED25519_BYTES = 64;
	private final static int ED25519_PUBLICKEYBYTES = 32;
	private final static int ED25519_SECRETKEYBYTES = 64;

	// blake2b
	abstract public boolean blake2b(byte[] out, byte[] key, byte[]... in);

	// XChaCha20Xor
	abstract public boolean xChaCha20Xor(byte[] out, byte[] in, byte[] nonce, byte[] key);

	// Ed25519
	abstract public boolean ed25519Sign(byte[] sig, byte[] m, byte[] sk);

	abstract public boolean ed25519Verify(byte[] sig, byte[] m, byte[] pk);

	abstract public byte[] ed25519SkToPk(byte[] sk);

	abstract public Pair<byte[], byte[]> ed25519Generate();

	// XChaCha20Poly1305
	public int getXchacha20XorKeybytes() {
		return XCHACHA20_XOR_KEY_BYTES;
	}

	public int getXchacha20XorNpubbytes() {
		return XCHACHA20_XOR_NONCE_BYTES;
	}

	// Nonce
	public NonceGenerator getNonceGenerator() {
		return this;
	}

	// Ed25519
	public int ed25519SignBytes() {
		return ED25519_BYTES;
	}

	public int ed25519SignPublicKeyBytes() {
		return ED25519_PUBLICKEYBYTES;
	}

	public int ed25519SignSecretKeyBytes() {
		return ED25519_SECRETKEYBYTES;
	}

	// Validation
	protected void validateBlake2b(byte[] out, byte[] key, byte[]... in) {
		// check for nulls
		if (out == null) { throw new NullPointerException("out"); }
		if (in == null || in.length == 0) { throw new NullPointerException("in"); }
		if (key == null) { throw new NullPointerException("key"); }

		// check lengths
		if (out.length < BLAKE2B_BYTES_MIN || out.length > BLAKE2B_BYTES_MAX) {
			throw new ByteArrayRangeException("out", out.length, BLAKE2B_BYTES_MIN, BLAKE2B_BYTES_MAX);
		}
		if (key.length < BLAKE2B_KEYBYTES_MIN || key.length > BLAKE2B_KEYBYTES_MAX) {
			throw new ByteArrayRangeException("key", key.length, BLAKE2B_KEYBYTES_MIN, BLAKE2B_KEYBYTES_MAX);
		}
	}

	protected void validateXChaCha20Xor(byte[] out, byte[] in, byte[] nonce, byte[] key) {
		// check for nulls
		if (out == null) { throw new NullPointerException("out"); }
		if (in == null) { throw new NullPointerException("in"); }
		if (nonce == null) { throw new NullPointerException("nonce"); }
		if (key == null) { throw new NullPointerException("key"); }


		if (key.length != XCHACHA20_XOR_KEY_BYTES) {
			throw new ByteArrayLengthException("key", key.length, XCHACHA20_XOR_KEY_BYTES);
		}
		if (nonce.length != XCHACHA20_XOR_NONCE_BYTES) {
			throw new ByteArrayLengthException("nonce", nonce.length, XCHACHA20_XOR_NONCE_BYTES);
		}
		if (out.length != in.length) {
			throw new ByteArrayLengthException("out", out.length, in.length);
		}
	}

	protected void validateEd25519Sign(byte[] sig, byte[] m, byte[] sk) {
		// check for nulls
		if (sig == null) { throw new NullPointerException("sig"); }
		if (m == null) { throw new NullPointerException("m"); }
		if (sk == null) { throw new NullPointerException("sk"); }

		// check lengths
		if (sig.length != ED25519_BYTES) { throw new ByteArrayLengthException("sig", sig.length, ED25519_BYTES); }
		if (m.length == 0) { throw new ByteArrayLengthException("m", 0, 1, false); }
		if (sk.length != ED25519_SECRETKEYBYTES) {
			throw new ByteArrayLengthException("sk", sk.length, ED25519_SECRETKEYBYTES);
		}
	}

	protected void validateEd25519Verify(byte[] sig, byte[] m, byte[] pk) {
		// check for nulls
		if (sig == null) { throw new NullPointerException("sig"); }
		if (m == null) { throw new NullPointerException("m"); }
		if (pk == null) { throw new NullPointerException("pk"); }

		// check lengths
		if (sig.length != ED25519_BYTES) { throw new ByteArrayLengthException("sig", sig.length, ED25519_BYTES); }
		if (m.length == 0) { throw new ByteArrayLengthException("m", 0, 1, false); }
		if (pk.length != ED25519_PUBLICKEYBYTES) {
			throw new ByteArrayLengthException("pk", pk.length, ED25519_PUBLICKEYBYTES);
		}
	}

	protected void validateEd25519PublicKey(byte[] sk) {
		if (sk == null) { throw new NullPointerException("sk"); }
		if (sk.length != ED25519_SECRETKEYBYTES) {
			throw new ByteArrayLengthException("sk", sk.length, ED25519_SECRETKEYBYTES);
		}
	}
}
