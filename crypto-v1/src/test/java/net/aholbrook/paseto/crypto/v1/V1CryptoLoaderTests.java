package net.aholbrook.paseto.crypto.v1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class V1CryptoLoaderTests {
	@Test
	public void serviceLoader() {
		Assertions.assertThrows(RuntimeException.class, V1CryptoLoader::getProvider);
	}
}
