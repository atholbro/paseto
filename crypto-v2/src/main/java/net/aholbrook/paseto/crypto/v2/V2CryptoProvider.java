package net.aholbrook.paseto.crypto.v2;

import net.aholbrook.paseto.crypto.KeyPair;
import net.aholbrook.paseto.crypto.NonceGenerator;
import net.aholbrook.paseto.crypto.exception.ByteArrayLengthException;
import net.aholbrook.paseto.crypto.exception.ByteArrayRangeException;

public abstract class V2CryptoProvider implements NonceGenerator {
	public final static int BLAKE2B_BYTES_MIN = 16;
	public final static int BLAKE2B_BYTES_MAX = 64;
	public final static int BLAKE2B_KEYBYTES_MIN = 16;
	public final static int BLAKE2B_KEYBYTES_MAX = 64;

	public final static int XCHACHA20_POLY1305_IETF_NPUBBYTES = 24; // nonce length
	public final static int XCHACHA20_POLY1305_IETF_ABYTES = 16;

	public final static int ED25519_BYTES = 64;
	public final static int ED25519_PUBLICKEYBYTES = 32;
	public final static int ED25519_SECRETKEYBYTES = 64;

	// blake2b
	abstract public boolean blake2b(byte[] out, byte[] in, byte[] key);

	// RNG
	abstract public byte[] randomBytes(int size);

	// XChaCha20Poly1305
	abstract public boolean aeadXChaCha20Poly1305IetfEncrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key);

	abstract public boolean aeadXChaCha20Poly1305IetfDecrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key);

	// Ed25519
	abstract public boolean ed25519Sign(byte[] sig, byte[] m, byte[] sk);

	abstract public boolean ed25519Verify(byte[] sig, byte[] m, byte[] pk);

	abstract public byte[] ed25519SkToPk(byte[] sk);

	abstract public KeyPair ed25519Generate();

	// Nonce
	public NonceGenerator getNonceGenerator() {
		return this;
	}

	@Override
	public byte[] generateNonce() {
		return randomBytes(XCHACHA20_POLY1305_IETF_NPUBBYTES);
	}

	// XChaCha20Poly1305
	public int xChaCha20Poly1305IetfNpubbytes() {
		return XCHACHA20_POLY1305_IETF_NPUBBYTES;
	}

	public int xChaCha20Poly1305IetfAbytes() {
		return XCHACHA20_POLY1305_IETF_ABYTES;
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
	protected void validateBlake2b(byte[] out, byte[] in, byte[] key) {
		// check for nulls
		if (out == null) { throw new NullPointerException("out"); }
		if (in == null) { throw new NullPointerException("in"); }
		if (key == null) { throw new NullPointerException("key"); }

		// check lengths
		if (out.length < BLAKE2B_BYTES_MIN || out.length > BLAKE2B_BYTES_MAX) {
			throw new ByteArrayRangeException("out", out.length, BLAKE2B_BYTES_MIN, BLAKE2B_BYTES_MAX);
		}
		if (key.length < BLAKE2B_KEYBYTES_MIN || key.length > BLAKE2B_KEYBYTES_MAX) {
			throw new ByteArrayRangeException("key", key.length, BLAKE2B_KEYBYTES_MIN, BLAKE2B_KEYBYTES_MAX);
		}
	}

	protected void validateAeadXChaCha20Poly1305Ietf(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) {
		// check for nulls
		if (out == null) { throw new NullPointerException("out"); }
		if (in == null) { throw new NullPointerException("in"); }
		if (ad == null) { throw new NullPointerException("ad"); }
		if (nonce == null) { throw new NullPointerException("nonce"); }
		if (key == null) { throw new NullPointerException("key"); }

		if (in.length == 0) {
			throw new ByteArrayLengthException("in", in.length, 1, false);
		}
		if (ad.length == 0) {
			throw new ByteArrayLengthException("ad", ad.length, 1, false);
		}
		if (key.length == 0) {
			throw new ByteArrayLengthException("key", key.length, 1, false);
		}

		if (nonce.length != XCHACHA20_POLY1305_IETF_NPUBBYTES) {
			throw new ByteArrayLengthException("nonce", nonce.length, XCHACHA20_POLY1305_IETF_NPUBBYTES);
		}
	}

	protected void validateAeadXChaCha20Poly1305IetfEncrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce,
			byte[] key) {
		validateAeadXChaCha20Poly1305Ietf(out, in, ad, nonce, key);

		// check lengths
		if (out.length != in.length + XCHACHA20_POLY1305_IETF_ABYTES) {
			throw new ByteArrayLengthException("out", out.length, in.length + XCHACHA20_POLY1305_IETF_ABYTES);
		}
	}

	protected void validateAeadXChaCha20Poly1305IetfDecrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce,
			byte[] key) {
		validateAeadXChaCha20Poly1305Ietf(out, in, ad, nonce, key);

		// check lengths
		if (out.length != in.length - XCHACHA20_POLY1305_IETF_ABYTES) {
			throw new ByteArrayLengthException("out", out.length, in.length - XCHACHA20_POLY1305_IETF_ABYTES);
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
