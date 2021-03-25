package net.aholbrook.paseto.encoding;

import java.util.ServiceLoader;

public class EncodingLoader {
	private EncodingLoader() {}

	public static EncodingProvider getProvider() {
		ServiceLoader<EncodingProvider> loader = ServiceLoader.load(EncodingProvider.class);
		EncodingProvider provider = loader.iterator().next();
		if (provider == null) { throw new RuntimeException("Unable to load EncodingProvider."); }
		return provider;
	}
}
