package net.aholbrook.paseto.encoding;

import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.encoding.json.jackson.JacksonJsonProvider;

public class StaticEncodingProvider {
	public static EncodingProvider newInstance() {
		return new JacksonJsonProvider();
	}
}
