package net.aholbrook.paseto.crypto.v2.bc;

import java.util.ServiceLoader;

public class V2CryptoLoader {
	private V2CryptoLoader() {}

	public static V2CryptoProvider getProvider() {
		ServiceLoader<V2CryptoProvider> loader = ServiceLoader.load(V2CryptoProvider.class);
		V2CryptoProvider provider = loader.iterator().next();
		if (provider == null) { throw new RuntimeException("Unable to load V2CryptoProvider."); }
		return provider;
	}
}
