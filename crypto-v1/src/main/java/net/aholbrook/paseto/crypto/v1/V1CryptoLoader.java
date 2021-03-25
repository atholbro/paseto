package net.aholbrook.paseto.crypto.v1;

import java.util.ServiceLoader;

public class V1CryptoLoader {
	private V1CryptoLoader() {}

	public static V1CryptoProvider getProvider() {
		ServiceLoader<V1CryptoProvider> loader = ServiceLoader.load(V1CryptoProvider.class);
		V1CryptoProvider provider = loader.iterator().next();
		if (provider == null) { throw new RuntimeException("Unable to load V1CryptoProvider."); }
		return provider;
	}
}
