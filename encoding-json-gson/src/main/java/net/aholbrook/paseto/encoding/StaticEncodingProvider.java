package net.aholbrook.paseto.encoding;

import net.aholbrook.paseto.encoding.json.gson.GsonJsonProvider;

public class StaticEncodingProvider {
	public static EncodingProvider newInstance() {
		return new GsonJsonProvider();
	}
}
