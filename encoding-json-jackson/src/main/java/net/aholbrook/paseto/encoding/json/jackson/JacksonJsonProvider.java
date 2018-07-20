/*
Copyright 2018 Andrew Holbrook

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package net.aholbrook.paseto.encoding.json.jackson;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import net.aholbrook.paseto.encoding.exception.EncodingException;
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
