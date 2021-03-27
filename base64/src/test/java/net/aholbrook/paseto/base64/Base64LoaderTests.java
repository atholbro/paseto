package net.aholbrook.paseto.base64;

import net.aholbrook.paseto.base64.jvm8.Base64Loader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Base 64 Loader")
public class Base64LoaderTests {
	@Test
	@DisplayName("Service Loader fails if no base 64 provider is on the classpath.")
	public void serviceLoader() {
		Assertions.assertThrows(RuntimeException.class, Base64Loader::getProvider);
	}
}
