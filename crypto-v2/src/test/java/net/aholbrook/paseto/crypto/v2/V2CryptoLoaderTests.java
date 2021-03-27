package net.aholbrook.paseto.crypto.v2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class V2CryptoLoaderTests {
	@Test
	public void serviceLoader() {
		Assertions.assertThrows(RuntimeException.class, V2CryptoLoader::getProvider);
	}
}
