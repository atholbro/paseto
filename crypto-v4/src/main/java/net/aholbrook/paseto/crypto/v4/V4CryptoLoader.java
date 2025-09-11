package net.aholbrook.paseto.crypto.v4;

import java.util.ServiceLoader;

public class V4CryptoLoader {
	private V4CryptoLoader() {}

	public static V4CryptoProvider getProvider() {
		try {
			ServiceLoader<V4CryptoProvider> loader = ServiceLoader.load(V4CryptoProvider.class);
			return loader.iterator().next();
		} catch (Throwable e) {
			throw new RuntimeException("Unable to load V4CryptoProvider.");
		}
	}
}
