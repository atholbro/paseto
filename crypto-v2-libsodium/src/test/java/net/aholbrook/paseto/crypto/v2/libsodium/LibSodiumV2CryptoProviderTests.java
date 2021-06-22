package net.aholbrook.paseto.crypto.v2.libsodium;

import com.goterl.lazysodium.Sodium;
import net.aholbrook.paseto.crypto.v2.V2CryptoLoader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

@DisplayName("Crypto :: v2 :: libsodium")
public class LibSodiumV2CryptoProviderTests {
	@Test
	@DisplayName("Can load LibSodiumV2CryptoProvider via the ServiceLoader.")
	public void serviceLoader() {
		Assertions.assertNotNull(V2CryptoLoader.getProvider(), "get provider");
	}

	@Test
	@DisplayName("blake2b fails if validation is wrong.")
	public void blake2b_fail() {
		byte[] bytes = new byte[1];

		Sodium sodium = Mockito.mock(Sodium.class);
		Mockito.when(sodium.crypto_generichash(bytes, bytes.length, bytes, bytes.length, bytes, bytes.length))
				.thenReturn(1);
		LibSodiumV2CryptoProvider provider = new NoValidationLibSodiumV2CryptoProvider(sodium);

		Assertions.assertFalse(provider.blake2b(bytes, bytes, bytes));
	}

	@Test
	@DisplayName("aeadXChaCha20Poly1305IetfEncrypt fails if validation is wrong.")
	public void aeadXChaCha20Poly1305IetfEncrypt_fail() {
		byte[] bytes = new byte[1];

		Sodium sodium = Mockito.mock(Sodium.class);
		Mockito.when(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
				bytes, null, bytes, bytes.length, bytes, bytes.length, null, bytes, bytes))
				.thenReturn(1);
		LibSodiumV2CryptoProvider provider = new NoValidationLibSodiumV2CryptoProvider(sodium);

		Assertions.assertFalse(provider.aeadXChaCha20Poly1305IetfEncrypt(bytes, bytes, bytes, bytes, bytes));
	}

	@Test
	@DisplayName("aeadXChaCha20Poly1305IetfDecrypt fails if validation is wrong.")
	public void aeadXChaCha20Poly1305IetfDecrypt_fail() {
		byte[] bytes = new byte[1];

		Sodium sodium = Mockito.mock(Sodium.class);
		Mockito.when(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
				bytes, null, null, bytes, bytes.length, bytes, bytes.length, bytes, bytes))
				.thenReturn(1);
		LibSodiumV2CryptoProvider provider = new NoValidationLibSodiumV2CryptoProvider(sodium);

		Assertions.assertFalse(provider.aeadXChaCha20Poly1305IetfDecrypt(bytes, bytes, bytes, bytes, bytes));
	}

	@Test
	@DisplayName("ed25519Sign fails with invalid inputs if validation is wrong.")
	public void ed25519Sign_fail() {
		byte[] bytes = new byte[1];

		Sodium sodium = Mockito.mock(Sodium.class);
		Mockito.when(sodium.crypto_sign_detached(
				bytes, null, bytes, bytes.length, bytes))
				.thenReturn(1);
		LibSodiumV2CryptoProvider provider = new NoValidationLibSodiumV2CryptoProvider(sodium);

		Assertions.assertFalse(provider.ed25519Sign(bytes, bytes, bytes));
	}

	@Test
	@DisplayName("ed25519Verify fails if validation is wrong.")
	public void ed25519Verify_fail() {
		byte[] bytes = new byte[1];

		Sodium sodium = Mockito.mock(Sodium.class);
		Mockito.when(sodium.crypto_sign_verify_detached(
				bytes, bytes, bytes.length, bytes))
				.thenReturn(1);
		LibSodiumV2CryptoProvider provider = new NoValidationLibSodiumV2CryptoProvider(sodium);

		Assertions.assertFalse(provider.ed25519Verify(bytes, bytes, bytes));
	}

	private static class NoValidationLibSodiumV2CryptoProvider extends LibSodiumV2CryptoProvider {
		public NoValidationLibSodiumV2CryptoProvider(Sodium sodium) {
			super(sodium);
		}

		@Override
		protected void validateBlake2b(byte[] out, byte[] in, byte[] key) { }

		@Override
		protected void validateAeadXChaCha20Poly1305Ietf(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) { }

		@Override
		protected void validateAeadXChaCha20Poly1305IetfEncrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) { }

		@Override
		protected void validateAeadXChaCha20Poly1305IetfDecrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) { }

		@Override
		protected void validateEd25519Sign(byte[] sig, byte[] m, byte[] sk) { }

		@Override
		protected void validateEd25519Verify(byte[] sig, byte[] m, byte[] pk) { }

		@Override
		protected void validateEd25519PublicKey(byte[] sk) { }
	};
}
