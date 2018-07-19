package net.aholbrook.paseto.encoding.json.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import net.aholbrook.paseto.service.Token;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

public class OffsetDateTimeSerializer extends JsonSerializer<OffsetDateTime> {
	@Override
	public void serialize(OffsetDateTime value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
		if (value == null) {
			gen.writeNull();
		} else {
			gen.writeString(Token.DATETIME_FORMATTER.format(value));
		}
	}

}