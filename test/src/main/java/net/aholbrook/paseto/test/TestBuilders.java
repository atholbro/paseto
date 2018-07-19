package net.aholbrook.paseto.test;


import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.crypto.v1.V1CryptoProvider;
import net.aholbrook.paseto.crypto.v2.base.V2CryptoProvider;
import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.Token;
import org.reflections.Reflections;

import java.util.Set;

public interface TestBuilders {
	<_TokenType> Paseto.Builder<_TokenType> pasetoBuilderV1(byte[] nonce);
	<_TokenType extends Token>LocalTokenService.Builder<_TokenType> localServiceBuilderV1(byte[] nonce,
			LocalTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass);
	<_TokenType extends Token>PublicTokenService.Builder<_TokenType> publicServiceBuilderV1(
			PublicTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass);
	
	<_TokenType> Paseto.Builder<_TokenType> pasetoBuilderV2(byte[] nonce);
	<_TokenType extends Token>LocalTokenService.Builder<_TokenType> localServiceBuilderV2(byte[] nonce,
			LocalTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass);
	<_TokenType extends Token>PublicTokenService.Builder<_TokenType> publicServiceBuilderV2(
			PublicTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass);

	EncodingProvider encodingProvider();
	V1CryptoProvider v1CryptoProvider();
	V2CryptoProvider v2CryptoProvider();

	class Cache {
		private static TestBuilders TEST_BUILDERS = null;
	}

	static TestBuilders find() {
		if (Cache.TEST_BUILDERS == null) {
			Reflections reflections = new Reflections("net.aholbrook.paseto");
			Set<Class<?>> classes = reflections.getTypesAnnotatedWith(Provided.class);

			for (Class<?> clazz : classes) {
				if (TestBuilders.class.isAssignableFrom(clazz)) {
					try {
						Cache.TEST_BUILDERS = (TestBuilders) clazz.newInstance();
						return Cache.TEST_BUILDERS;
					} catch (Throwable e) {
						// ignore
					}
				}
			}

			throw new RuntimeException("Unable to locate TestBuilders. Please create a subclass of TestBuilders and mark it"
					+ " with @Provided.");
		}

		return Cache.TEST_BUILDERS;
	}
}
