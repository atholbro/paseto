package net.aholbrook.paseto.crypto.v1.bc;

import net.aholbrook.paseto.crypto.KeyPair;
import net.aholbrook.paseto.crypto.exception.CryptoProviderException;
import net.aholbrook.paseto.crypto.v1.V1CryptoLoader;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;

@DisplayName("Crypto :: v1 :: BouncyCastle")
public class BouncyCastleV1CryptoProviderTests {
	private byte[] m = new byte[16];
	private byte[] key = new byte[16];
	private byte[] iv = new byte[8];

	// TODO hardcode a result for keypair.
	private KeyPair keyPair = new BouncyCastleV1CryptoProvider().rsaGenerate();

	public void withAse256CtrCipherMocks(Consumer<BouncyCastleV1CryptoProvider> test) {
		BouncyCastleV1CryptoProvider provider = Mockito.spy(BouncyCastleV1CryptoProvider.class);
		BufferedBlockCipher bufferedBlockCipher = Mockito.mock(BufferedBlockCipher.class);

		Mockito.when(provider.aes256CtrCipher(true, key, iv)).thenReturn(bufferedBlockCipher);
		Mockito.when(provider.aes256CtrCipher(false, key, iv)).thenReturn(bufferedBlockCipher);

		try {
			Mockito.when(bufferedBlockCipher.doFinal(any(), anyInt())).thenThrow(new InvalidCipherTextException("mocked"));
		} catch (InvalidCipherTextException e) {
			// ignore
		}

		test.accept(provider);
	}

	@Test
	@DisplayName("aes256CtrEncrypt correctly handles an InvalidCipherTextException if thrown.")
	public void aes256CtrEncrypt_InvalidCipherTextException() {
		withAse256CtrCipherMocks((provider) -> {
			Assertions.assertThrows(CryptoProviderException.class, () -> provider.aes256CtrEncrypt(m, key, iv));
		});
	}

	@Test
	@DisplayName("aes256CtrDecrypt correctly handles an InvalidCipherTextException if thrown.")
	public void aes256CtrDecrypt_InvalidCipherTextException() {
		withAse256CtrCipherMocks((provider) -> {
			Assertions.assertThrows(CryptoProviderException.class, () -> provider.aes256CtrDecrypt(m, key, iv));
		});
	}

	public void withPssSha384Mocks(Consumer<BouncyCastleV1CryptoProvider> test) {
		BouncyCastleV1CryptoProvider provider = Mockito.spy(BouncyCastleV1CryptoProvider.class);
		PSSSigner pssSigner = Mockito.mock(PSSSigner.class);

		Mockito.when(provider.pssSha384(true, keyPair.getSecretKey())).thenReturn(pssSigner);
		Mockito.when(provider.pssSha384(false, keyPair.getPublicKey())).thenReturn(pssSigner);

		try {
			Mockito.when(pssSigner.generateSignature())
					.thenThrow(new CryptoException("mocked", new RuntimeException()));
		} catch (CryptoException e) {
			// ignore
		}

		test.accept(provider);
	}

	@Test
	@DisplayName("rsaSign correctly handles a CryptoException if thrown.")
	public void rsaSign_CryptoProviderException() {
		withPssSha384Mocks((provider) -> {
			Assertions.assertThrows(CryptoProviderException.class, () -> provider.rsaSign(m, keyPair.getSecretKey()));
		});
	}

	@Test
	@DisplayName("Can load BouncyCastleV1CryptoProvider via the ServiceLoader.")
	public void serviceLoader() {
		Assertions.assertNotNull(V1CryptoLoader.getProvider(), "get provider");
	}
}
