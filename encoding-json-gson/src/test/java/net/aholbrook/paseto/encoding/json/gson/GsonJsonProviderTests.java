package net.aholbrook.paseto.encoding.json.gson;

import net.aholbrook.paseto.encoding.EncodingLoader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;

@DisplayName("Encoding :: GSON")
public class GsonJsonProviderTests {
	@Test
	@DisplayName("Can load GsonJsonProvider via the ServiceLoader.")
	public void serviceLoader() {
		Assertions.assertNotNull(EncodingLoader.getProvider(), "get provider");
	}

	@Test
	@DisplayName("Attempt to deserialize an OffsetDateTime that's an object results in the field being null.")
	public void offsetDateTimeAsObject() {
		TestObject testObject = new GsonJsonProvider().decode("{\"time\":{\"time\":0}}", TestObject.class);
		Assertions.assertNotNull(testObject);
		Assertions.assertNull(testObject.time);
	}

	public static class TestObject {
		public OffsetDateTime time;
	}
}
