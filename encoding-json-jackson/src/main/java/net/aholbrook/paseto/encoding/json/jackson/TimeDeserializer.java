package net.aholbrook.paseto.encoding.json.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import net.aholbrook.paseto.service.Token;

import java.io.IOException;

public class TimeDeserializer extends JsonDeserializer<Long> {

	@Override
	public Long deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JsonProcessingException {
		JsonToken token = p.getCurrentToken();

		if (token.equals(JsonToken.VALUE_STRING)) {
			return Token.DATETIME_FORMATTER.parse(p.getValueAsString()).toEpochSecond();
		} else {
			return getNullValue(ctxt);
		}
	}

}
