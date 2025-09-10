package net.aholbrook.paseto.encoding.json.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import net.aholbrook.paseto.service.Token;

import java.io.IOException;
import java.time.OffsetDateTime;

public class TimeDeserializer extends JsonDeserializer<Long> {
	@Override
	public Long deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
		JsonToken token = p.getCurrentToken();

		if (token.equals(JsonToken.VALUE_STRING)) {
			return OffsetDateTime.parse(p.getValueAsString(), Token.DATETIME_FORMATTER).toEpochSecond();
		} else {
			return getNullValue(ctxt);
		}
	}
}
