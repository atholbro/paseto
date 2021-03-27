package net.aholbrook.paseto.crypto.v2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Crypto :: v2 :: BouncyCastle")
public class BouncyCastleV2CryptoProviderTests {
	@Test
	@DisplayName("Can load BouncyCastleV2CryptoProvider via the ServiceLoader.")
	public void serviceLoader() {
		Assertions.assertNotNull(V2CryptoLoader.getProvider(), "get provider");
	}
}
