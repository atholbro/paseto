package net.aholbrook.paseto.encoding.json.gson;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.encoding.exception.EncodingException;

import java.time.OffsetDateTime;

public class GsonJsonProvider implements EncodingProvider {
	private final Gson gson;

	public GsonJsonProvider() {
		this(new GsonBuilder());
	}

	public GsonJsonProvider(GsonBuilder gsonBuilder) {
		gsonBuilder.registerTypeAdapter(OffsetDateTime.class, new OffsetDateTimeSerializer());
		gsonBuilder.registerTypeAdapter(OffsetDateTime.class, new OffsetDateTimeDeserializer());
		this.gson = gsonBuilder.create();
	}

	@Override
	public String encode(Object o) {
		if (o == null) { return null; }
		return gson.toJson(o);
	}

	@Override
	public <_Out> _Out decode(String s, Class<_Out> clazz) {
		if (s == null) { return null; }

		try {
			_Out out = gson.fromJson(s, clazz);
			if (out == null) { throw new EncodingException("Error while decoding json: null output", new Throwable()); }

			return out;
		} catch (JsonSyntaxException e) {
			throw new EncodingException("Error while decoding json.", e);
		}
	}
}
