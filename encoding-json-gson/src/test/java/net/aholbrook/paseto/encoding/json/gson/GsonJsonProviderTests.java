package net.aholbrook.paseto.encoding.json.gson;

import net.aholbrook.paseto.encoding.EncodingLoader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class GsonJsonProviderTests {
	@Test
	public void serviceLoader() {
		Assertions.assertNotNull(EncodingLoader.getProvider(), "get provider");
	}
}
