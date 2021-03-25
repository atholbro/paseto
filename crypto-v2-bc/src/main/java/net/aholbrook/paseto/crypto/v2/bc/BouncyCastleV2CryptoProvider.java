package net.aholbrook.paseto.crypto.v2.bc;

import net.aholbrook.paseto.crypto.KeyPair;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;

public class BouncyCastleV2CryptoProvider extends V2CryptoProvider {
	private final SecureRandom rng = new SecureRandom();

	@Override
	public boolean blake2b(byte[] out, byte[] in, byte[] key) {
		validateBlake2b(out, in, key);
		Digest digest = new Blake2bDigest(key, 24, null, null);
		digest.update(in, 0, in.length);
		try {
			digest.doFinal(out, 0);
		} catch (Throwable e) {
			throw e;
		}
		return true;
	}

	@Override
	public byte[] randomBytes(int size) {
		byte[] buffer = new byte[size];
		rng.nextBytes(buffer);
		return buffer;
	}

	@Override
	public boolean aeadXChaCha20Poly1305IetfEncrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) {
		validateAeadXChaCha20Poly1305IetfEncrypt(out, in, ad, nonce, key);
		return AeadXChaCha20Poly1305Ietf.encrypt(out, in, ad, nonce, key);
	}

	@Override
	public boolean aeadXChaCha20Poly1305IetfDecrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) {
		validateAeadXChaCha20Poly1305IetfDecrypt(out, in, ad, nonce, key);
		return AeadXChaCha20Poly1305Ietf.decrypt(out, in, ad, nonce, key);
	}

	@Override
	public boolean ed25519Sign(byte[] sig, byte[] m, byte[] sk) {
		validateEd25519Sign(sig, m, sk);
		try {
			CipherParameters params = new Ed25519PrivateKeyParameters(sk, 0);
			Ed25519Signer ed25519 = new Ed25519Signer();
			ed25519.init(true, params);
			ed25519.update(m, 0, m.length);
			byte[] result = ed25519.generateSignature();
			System.arraycopy(result, 0, sig, 0, sig.length);
			return true;
		} catch (Throwable e) {
			return false;
		}
	}

	@Override
	public boolean ed25519Verify(byte[] sig, byte[] m, byte[] pk) {
		validateEd25519Verify(sig, m, pk);
		try {
			CipherParameters params = new Ed25519PublicKeyParameters(pk, 0);
			Ed25519Signer ed25519 = new Ed25519Signer();
			ed25519.init(false, params);
			ed25519.update(m, 0, m.length);
			return ed25519.verifySignature(sig);
		} catch (Throwable e) {
			return false;
		}
	}

	@Override
	public byte[] ed25519SkToPk(byte[] sk) {
		validateEd25519PublicKey(sk);
		byte[] pk = new byte[ed25519SignPublicKeyBytes()];

		Ed25519PrivateKeyParameters params = new Ed25519PrivateKeyParameters(sk, 0);
		Ed25519PublicKeyParameters pkParams = params.generatePublicKey();
		System.arraycopy(pkParams.getEncoded(), 0, pk, 0, pk.length);

		return pk;
	}

	@Override
	public KeyPair ed25519Generate() {
		int skLen = ed25519SignSecretKeyBytes() - ed25519SignPublicKeyBytes();
		byte[] sk = new byte[ed25519SignSecretKeyBytes()];
		byte[] pk = new byte[ed25519SignPublicKeyBytes()];

		Ed25519PrivateKeyParameters params = new Ed25519PrivateKeyParameters(rng);
		Ed25519PublicKeyParameters pkParams = params.generatePublicKey();

		System.arraycopy(params.getEncoded(), 0, sk, 0, skLen);
		System.arraycopy(pkParams.getEncoded(), 0, sk, skLen, pk.length);
		System.arraycopy(sk, skLen, pk, 0, pk.length);

		return new KeyPair(sk, pk);
	}
}
