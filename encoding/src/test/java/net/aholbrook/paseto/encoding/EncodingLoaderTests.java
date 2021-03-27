package net.aholbrook.paseto.encoding;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Encoding Loader")
public class EncodingLoaderTests {
	@Test
	@DisplayName("Service Loader fails if no encoding provider is on the classpath.")
	public void serviceLoader() {
		Assertions.assertThrows(RuntimeException.class, EncodingLoader::getProvider);
	}
}
