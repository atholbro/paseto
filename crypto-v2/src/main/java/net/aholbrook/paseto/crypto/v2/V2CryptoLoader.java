package net.aholbrook.paseto.crypto.v2;

import java.util.ServiceLoader;

public class V2CryptoLoader {
	private V2CryptoLoader() {}

	public static V2CryptoProvider getProvider() {
		try {
			ServiceLoader<V2CryptoProvider> loader = ServiceLoader.load(V2CryptoProvider.class);
			return loader.iterator().next();
		} catch (Throwable e) {
			throw new RuntimeException("Unable to load V2CryptoProvider.");
		}
	}
}
