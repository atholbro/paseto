package net.aholbrook.paseto.encoding.json.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

public class OffsetDateTimeSerializer extends JsonSerializer<OffsetDateTime> {
	public final static DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssxxxxx");

	@Override
	public void serialize(OffsetDateTime value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
		if (value == null) {
			gen.writeNull();
		} else {
			gen.writeString(FORMATTER.format(value));
		}
	}

}