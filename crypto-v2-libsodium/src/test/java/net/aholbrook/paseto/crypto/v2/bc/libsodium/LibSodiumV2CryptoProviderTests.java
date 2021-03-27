package net.aholbrook.paseto.crypto.v2.bc.libsodium;

import net.aholbrook.paseto.crypto.v2.bc.V2CryptoLoader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LibSodiumV2CryptoProviderTests {
	@Test
	public void serviceLoader() {
		Assertions.assertNotNull(V2CryptoLoader.getProvider(), "get provider");
	}
}
