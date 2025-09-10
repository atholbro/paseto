package net.aholbrook.paseto.encoding.json.gson;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import net.aholbrook.paseto.service.Token;

import java.lang.reflect.Type;
import java.time.OffsetDateTime;

public class OffsetDateTimeDeserializer implements JsonDeserializer<OffsetDateTime> {
	@Override
	public OffsetDateTime deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
			throws JsonParseException {

		if (json.isJsonPrimitive() && json.getAsJsonPrimitive().isString()) {
			return OffsetDateTime.parse(json.getAsString(), Token.DATETIME_FORMATTER);
		} else {
			return null;
		}
	}
}
