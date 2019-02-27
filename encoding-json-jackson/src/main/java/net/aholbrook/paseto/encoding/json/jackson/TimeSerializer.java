package net.aholbrook.paseto.encoding.json.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.time.OffsetDateTime;

import java.io.IOException;

public class TimeSerializer extends JsonSerializer<Long> {
	@Override
	public void serialize(Long value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
		gen.writeString(Token.DATETIME_FORMATTER.format(OffsetDateTime.ofEpochSecond(value)));
	}

}