package net.aholbrook.paseto.encoding;

import java.util.ServiceLoader;

public class EncodingLoader {
	private EncodingLoader() {}

	public static EncodingProvider getProvider() {
		try {
			ServiceLoader<EncodingProvider> loader = ServiceLoader.load(EncodingProvider.class);
			return loader.iterator().next();
		} catch (Throwable e) {
			throw new RuntimeException("Unable to load EncodingProvider.");
		}
	}
}
