package net.aholbrook.paseto.crypto.v1;

import java.util.ServiceLoader;

public class V1CryptoLoader {
	private V1CryptoLoader() {}

	public static V1CryptoProvider getProvider() {
		try {
			ServiceLoader<V1CryptoProvider> loader = ServiceLoader.load(V1CryptoProvider.class);
			return loader.iterator().next();
		} catch (Throwable e) {
			throw new RuntimeException("Unable to load V1CryptoProvider.", e);
		}
	}
}
