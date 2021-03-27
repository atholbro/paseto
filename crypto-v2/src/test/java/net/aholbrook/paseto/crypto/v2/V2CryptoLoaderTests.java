package net.aholbrook.paseto.crypto.v2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("V2 Cyrpto Loader")
public class V2CryptoLoaderTests {
	@Test
	@DisplayName("Service Loader fails if no v2 crypto provider is on the classpath.")
	public void serviceLoader() {
		Assertions.assertThrows(RuntimeException.class, V2CryptoLoader::getProvider);
	}
}
