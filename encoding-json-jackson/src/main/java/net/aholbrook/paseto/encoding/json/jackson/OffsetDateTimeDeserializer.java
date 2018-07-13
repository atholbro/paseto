package net.aholbrook.paseto.encoding.json.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.time.OffsetDateTime;

public class OffsetDateTimeDeserializer extends JsonDeserializer<OffsetDateTime> {

	@Override
	public OffsetDateTime deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JsonProcessingException {
		JsonToken token = p.getCurrentToken();

		if (token.equals(JsonToken.VALUE_STRING)) {
			return OffsetDateTimeSerializer.FORMATTER.parse(p.getValueAsString(), OffsetDateTime::from);
		} else {
			return getNullValue(ctxt);
		}
	}

}
