package net.aholbrook.paseto.crypto.v4;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("V4 Cyrpto Loader")
public class V4CryptoLoaderTests {
	@Test
	@DisplayName("Service Loader fails if no v4 crypto provider is on the classpath.")
	public void serviceLoader() {
		Assertions.assertThrows(RuntimeException.class, V4CryptoLoader::getProvider);
	}
}
