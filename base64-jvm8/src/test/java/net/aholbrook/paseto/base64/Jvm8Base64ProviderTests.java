package net.aholbrook.paseto.base64;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Jvm8Base64ProviderTests {
	@Test
	public void serviceLoader() {
		Assertions.assertNotNull(Base64Loader.getProvider(), "get provider");
	}
}
