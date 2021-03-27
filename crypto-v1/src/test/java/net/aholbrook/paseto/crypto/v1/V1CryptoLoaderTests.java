package net.aholbrook.paseto.crypto.v1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("V1 Cyrpto Loader")
public class V1CryptoLoaderTests {
	@Test
	@DisplayName("Service Loader fails if no v1 crypto provider is on the classpath.")
	public void serviceLoader() {
		Assertions.assertThrows(RuntimeException.class, V1CryptoLoader::getProvider);
	}
}
