package net.aholbrook.paseto.base64.jvm8;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Base 64 :: JVM8")
public class Jvm8Base64ProviderTests {
	@Test
	@DisplayName("Can load Jvm8Base64Provider via the ServiceLoader.")
	public void serviceLoader() {
		Assertions.assertNotNull(Base64Loader.getProvider(), "get provider");
	}
}
