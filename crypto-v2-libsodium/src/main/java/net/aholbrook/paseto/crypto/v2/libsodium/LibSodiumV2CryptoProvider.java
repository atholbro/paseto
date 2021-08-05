package net.aholbrook.paseto.crypto.v2.libsodium;

import com.goterl.lazysodium.SodiumJava;
import net.aholbrook.paseto.crypto.KeyPair;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;

public class LibSodiumV2CryptoProvider extends V2CryptoProvider {
	protected final SodiumJava sodium;

	public LibSodiumV2CryptoProvider() {
		this(new SodiumJava());
	}

	public LibSodiumV2CryptoProvider(SodiumJava sodium) {
		this.sodium = sodium;
	}

	@Override
	public boolean blake2b(byte[] out, byte[] in, byte[] key) {
		validateBlake2b(out, in, key);
		return sodium.crypto_generichash(out, out.length, in, in.length, key, key.length) == 0;
	}

	@Override
	public byte[] randomBytes(int size) {
		byte[] buffer = new byte[size];
		sodium.randombytes_buf(buffer, size);
		return buffer;
	}

	@Override
	public boolean aeadXChaCha20Poly1305IetfEncrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) {
		validateAeadXChaCha20Poly1305IetfEncrypt(out, in, ad, nonce, key);

		return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(out, null, in, in.length, ad, ad.length, null,
				nonce, key) == 0;
	}

	@Override
	public boolean aeadXChaCha20Poly1305IetfDecrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) {
		validateAeadXChaCha20Poly1305IetfDecrypt(out, in, ad, nonce, key);

		return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(out, null, null, in, in.length, ad, ad.length,
				nonce, key) == 0;
	}

	@Override
	public boolean ed25519Sign(byte[] sig, byte[] m, byte[] sk) {
		validateEd25519Sign(sig, m, sk);

		return sodium.crypto_sign_detached(sig, null, m, m.length, sk) == 0;
	}

	@Override
	public boolean ed25519Verify(byte[] sig, byte[] m, byte[] pk) {
		validateEd25519Verify(sig, m, pk);
		return sodium.crypto_sign_verify_detached(sig, m, m.length, pk) == 0;
	}

	@Override
	public byte[] ed25519SkToPk(byte[] sk) {
		validateEd25519PublicKey(sk);
		byte[] pk = new byte[ed25519SignPublicKeyBytes()];


		sodium.crypto_sign_ed25519_sk_to_pk(pk, sk);
		return pk;
	}

	@Override
	public KeyPair ed25519Generate() {
		byte[] sk = new byte[ed25519SignSecretKeyBytes()];
		byte[] pk = new byte[ed25519SignPublicKeyBytes()];
		sodium.crypto_sign_keypair(pk, sk);
		return new KeyPair(sk, pk);
	}
}
