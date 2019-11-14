package net.aholbrook.paseto.meta;

import net.aholbrook.paseto.PasetoV1;
import net.aholbrook.paseto.PasetoV2;
import net.aholbrook.paseto.base64.jvm8.Jvm8Base64Provider;
import net.aholbrook.paseto.crypto.v1.bc.BouncyCastleV1CryptoProvider;
import net.aholbrook.paseto.crypto.v2.libsodium.LibSodiumV2CryptoProvider;
import net.aholbrook.paseto.encoding.StaticEncodingProvider;
import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.Token;

public class PasetoBuilders {
	private PasetoBuilders() {
	}

	public static class V1 {
		private V1() {
		}

		public static PasetoV1.Builder paseto() {
			return new PasetoV1.Builder(new Jvm8Base64Provider(), StaticEncodingProvider.newInstance(),
					new BouncyCastleV1CryptoProvider());
		}

		public static <_TokenType extends Token> LocalTokenService.Builder<_TokenType> localService(
				LocalTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass) {
			PasetoV1.Builder paseto = paseto();
			return localService(paseto, keyProvider, tokenClass);
		}

		public static <_TokenType extends Token> LocalTokenService.Builder<_TokenType> localService(
				PasetoV1.Builder paseto, LocalTokenService.KeyProvider keyProvider,
				Class<_TokenType> tokenClass) {
			return new LocalTokenService.Builder<>(paseto.build(), tokenClass, keyProvider);
		}

		public static <_TokenType extends Token> PublicTokenService.Builder<_TokenType> publicService(
				PublicTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass) {
			PasetoV1.Builder paseto = paseto();
			return publicService(paseto, keyProvider, tokenClass);
		}

		public static <_TokenType extends Token> PublicTokenService.Builder<_TokenType> publicService(
				PasetoV1.Builder paseto, PublicTokenService.KeyProvider keyProvider,
				Class<_TokenType> tokenClass) {
			return new PublicTokenService.Builder<>(paseto.build(), tokenClass, keyProvider);
		}
	}

	public static class V2 {
		private V2() {
		}

		public static PasetoV2.Builder paseto() {
			return new PasetoV2.Builder(new Jvm8Base64Provider(), StaticEncodingProvider.newInstance(),
					new LibSodiumV2CryptoProvider());
		}

		public static <_TokenType extends Token> LocalTokenService.Builder<_TokenType> localService(
				LocalTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass) {
			PasetoV2.Builder paseto = paseto();
			return localService(paseto, keyProvider, tokenClass);
		}

		public static <_TokenType extends Token> LocalTokenService.Builder<_TokenType> localService(
				PasetoV2.Builder paseto, LocalTokenService.KeyProvider keyProvider,
				Class<_TokenType> tokenClass) {
			return new LocalTokenService.Builder<>(paseto.build(), tokenClass, keyProvider);
		}

		public static <_TokenType extends Token> PublicTokenService.Builder<_TokenType> publicService(
				PublicTokenService.KeyProvider keyProvider,
				Class<_TokenType> tokenClass) {
			PasetoV2.Builder paseto = paseto();
			return publicService(paseto, keyProvider, tokenClass);
		}

		public static <_TokenType extends Token> PublicTokenService.Builder<_TokenType> publicService(
				PasetoV2.Builder paseto, PublicTokenService.KeyProvider keyProvider,
				Class<_TokenType> tokenClass) {
			return new PublicTokenService.Builder<>(paseto.build(), tokenClass, keyProvider);
		}
	}
}
