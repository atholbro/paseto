package net.aholbrook.paseto.base64.jvm8;

import java.util.ServiceLoader;

public class Base64Loader {
	private Base64Loader() {}

	public static Base64Provider getProvider() {
		ServiceLoader<Base64Provider> loader = ServiceLoader.load(Base64Provider.class);
		Base64Provider provider = loader.iterator().next();
		if (provider == null) { throw new RuntimeException("Unable to load Base64Provider."); }
		return provider;
	}
}
