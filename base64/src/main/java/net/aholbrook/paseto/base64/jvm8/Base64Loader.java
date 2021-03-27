package net.aholbrook.paseto.base64.jvm8;

import java.util.ServiceLoader;

public class Base64Loader {
	private Base64Loader() {}

	public static Base64Provider getProvider() {
		try {
			ServiceLoader<Base64Provider> loader = ServiceLoader.load(Base64Provider.class);
			return loader.iterator().next();
		} catch (Throwable e) {
			throw new RuntimeException("Unable to load Base64Provider.", e);
		}
	}
}
