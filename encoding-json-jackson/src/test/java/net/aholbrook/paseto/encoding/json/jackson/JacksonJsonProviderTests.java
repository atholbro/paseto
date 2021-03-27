package net.aholbrook.paseto.encoding.json.jackson;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.aholbrook.paseto.encoding.EncodingLoader;
import net.aholbrook.paseto.encoding.exception.EncodingException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

@DisplayName("Encoding :: Jackson")
public class JacksonJsonProviderTests {
	@Test
	@DisplayName("Can load JacksonJsonProvider via the ServiceLoader.")
	public void serviceLoader() {
		Assertions.assertNotNull(EncodingLoader.getProvider(), "get provider");
	}

	@Test
	@DisplayName("encode correctly handles a JsonProcessingException if thrown.")
	public void testJsonProcessingException() {
		Assertions.assertThrows(EncodingException.class, () -> {
			JsonProcessingException ex = Mockito.mock(JsonProcessingException.class);
			ObjectMapper objectMapper = Mockito.mock(ObjectMapper.class);
			Mockito.when(objectMapper.writeValueAsString("")).thenThrow(ex);

			JacksonJsonProvider provider = new JacksonJsonProvider(objectMapper);
			provider.encode("");
		});
	}
}
