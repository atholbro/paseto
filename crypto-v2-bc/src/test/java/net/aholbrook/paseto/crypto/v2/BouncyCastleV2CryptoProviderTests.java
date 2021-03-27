package net.aholbrook.paseto.crypto.v2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class BouncyCastleV2CryptoProviderTests {
	@Test
	public void serviceLoader() {
		Assertions.assertNotNull(V2CryptoLoader.getProvider(), "get provider");
	}
}
