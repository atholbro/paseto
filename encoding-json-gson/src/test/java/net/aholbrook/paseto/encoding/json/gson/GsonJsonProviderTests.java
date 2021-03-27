package net.aholbrook.paseto.encoding.json.gson;

import net.aholbrook.paseto.encoding.EncodingLoader;
import net.aholbrook.paseto.time.OffsetDateTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class GsonJsonProviderTests {
	@Test
	public void serviceLoader() {
		Assertions.assertNotNull(EncodingLoader.getProvider(), "get provider");
	}

	@Test
	public void offsetDateTimeAsObject() {
		TestObject testObject = new GsonJsonProvider().decode("{\"time\":{\"time\":0}}", TestObject.class);
		Assertions.assertNotNull(testObject);
		Assertions.assertNull(testObject.time);
	}

	public static class TestObject {
		public OffsetDateTime time;
	}
}
