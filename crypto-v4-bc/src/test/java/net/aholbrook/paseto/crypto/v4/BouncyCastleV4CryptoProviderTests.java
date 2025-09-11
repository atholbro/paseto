package net.aholbrook.paseto.crypto.v4;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Crypto :: v4 :: BouncyCastle")
public class BouncyCastleV4CryptoProviderTests {
	@Test
	@DisplayName("Can load BouncyCastleV4CryptoProvider via the ServiceLoader.")
	public void serviceLoader() {
		Assertions.assertNotNull(V4CryptoLoader.getProvider(), "get provider");
	}
}
