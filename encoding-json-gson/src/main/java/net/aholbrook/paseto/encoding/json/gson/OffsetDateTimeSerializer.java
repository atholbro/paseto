package net.aholbrook.paseto.encoding.json.gson;

import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import net.aholbrook.paseto.service.Token;

import java.lang.reflect.Type;
import java.time.OffsetDateTime;

public class OffsetDateTimeSerializer implements JsonSerializer<OffsetDateTime> {
	@Override
	public JsonElement serialize(OffsetDateTime src, Type typeOfSrc, JsonSerializationContext context) {
		return new JsonPrimitive(Token.DATETIME_FORMATTER.format(src));
	}
}
