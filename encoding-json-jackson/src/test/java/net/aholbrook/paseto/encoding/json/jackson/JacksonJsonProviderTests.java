package net.aholbrook.paseto.encoding.json.jackson;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.aholbrook.paseto.encoding.exception.EncodingException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import org.mockito.Mockito;

public class JacksonJsonProviderTests {
	@Test
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
