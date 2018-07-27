package net.aholbrook.paseto.encoding.json.jackson;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import net.aholbrook.paseto.encoding.exception.EncodingException;
import net.aholbrook.paseto.encoding.json.jackson.mixin.KeyIdMixIn;
import net.aholbrook.paseto.encoding.json.jackson.mixin.TokenMixIn;
import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.encoding.EncodingProvider;

import java.io.IOException;
import java.time.OffsetDateTime;

public class JacksonJsonProvider implements EncodingProvider {
	private final ObjectMapper objectMapper;

	public JacksonJsonProvider() {
		this(new ObjectMapper());
		objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

		registerMixins(objectMapper);
		objectMapper.registerModule(offsetDateTimeModule());
	}

	public JacksonJsonProvider(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	@Override
	public String encode(Object o) {
		if (o == null) { return null; }

		try {
			return objectMapper.writeValueAsString(o);
		} catch (JsonProcessingException e) {
			throw new EncodingException("Error while encoding json.", e);
		}
	}

	@Override
	public <_Out> _Out decode(String s, Class<_Out> clazz) {
		if (s == null) { return null; }

		try {
			return objectMapper.readValue(s, clazz);
		} catch (IOException e) {
			throw new EncodingException("Error while decoding json.", e);
		}
	}

	public static void registerMixins(ObjectMapper mapper) {
		mapper.addMixIn(Token.class, TokenMixIn.class);
		mapper.addMixIn(KeyId.class, KeyIdMixIn.class);
	}

	public static SimpleModule offsetDateTimeModule() {
		SimpleModule module = new SimpleModule();
		module.addSerializer(OffsetDateTime.class, new OffsetDateTimeSerializer());
		module.addDeserializer(OffsetDateTime.class, new OffsetDateTimeDeserializer());
		return module;
	}
}
