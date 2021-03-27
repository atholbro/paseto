package net.aholbrook.paseto.base64;

import net.aholbrook.paseto.base64.jvm8.Base64Loader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Base64LoaderTests {
	@Test
	public void serviceLoader() {
		Assertions.assertThrows(RuntimeException.class, Base64Loader::getProvider);
	}
}
