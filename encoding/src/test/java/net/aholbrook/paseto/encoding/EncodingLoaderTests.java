package net.aholbrook.paseto.encoding;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class EncodingLoaderTests {
	@Test
	public void serviceLoader() {
		Assertions.assertThrows(RuntimeException.class, EncodingLoader::getProvider);
	}
}
