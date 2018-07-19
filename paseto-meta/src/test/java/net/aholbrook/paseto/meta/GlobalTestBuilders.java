package net.aholbrook.paseto.meta;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.crypto.v1.V1CryptoProvider;
import net.aholbrook.paseto.crypto.v1.bc.JvmV1CryptoProvider;
import net.aholbrook.paseto.crypto.v2.base.V2CryptoProvider;
import net.aholbrook.paseto.crypto.v2.libsodium.LibSodiumV2CryptoProvider;
import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.encoding.json.jackson.JacksonJsonProvider;
import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.test.Provided;
import net.aholbrook.paseto.test.TestBuilders;
import net.aholbrook.paseto.test.crypto.TestNonceGenerator;

@Provided
public class GlobalTestBuilders implements TestBuilders {
	@Override
	public  <_TokenType> Paseto.Builder<_TokenType> pasetoBuilderV1(byte[] nonce) {
		Paseto.Builder<_TokenType> builder = PasetoBuilders.V1.paseto();
		if (nonce != null) {
			builder.withTestingNonceGenerator(new TestNonceGenerator(nonce));
		}
		return builder;
	}

	@Override
	public <_TokenType extends Token> LocalTokenService.Builder<_TokenType> localServiceBuilderV1(byte[] nonce,
			LocalTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass) {
		return PasetoBuilders.V1.localService(this.pasetoBuilderV1(nonce), keyProvider, tokenClass);
	}

	@Override
	public <_TokenType extends Token> PublicTokenService.Builder<_TokenType> publicServiceBuilderV1(
			PublicTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass) {
		return PasetoBuilders.V1.publicService(this.pasetoBuilderV1(null), keyProvider, tokenClass);
	}

	@Override
	public <_TokenType> Paseto.Builder<_TokenType> pasetoBuilderV2(byte[] nonce) {
		Paseto.Builder<_TokenType> builder = PasetoBuilders.V2.paseto();
		if (nonce != null) {
			builder.withTestingNonceGenerator(new TestNonceGenerator(nonce));
		}
		return builder;
	}

	@Override
	public <_TokenType extends Token> LocalTokenService.Builder<_TokenType> localServiceBuilderV2(byte[] nonce,
			LocalTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass) {
		return PasetoBuilders.V2.localService(this.pasetoBuilderV2(nonce), keyProvider, tokenClass);
	}

	@Override
	public <_TokenType extends Token> PublicTokenService.Builder<_TokenType> publicServiceBuilderV2(
			PublicTokenService.KeyProvider keyProvider, Class<_TokenType> tokenClass) {
		return PasetoBuilders.V2.publicService(this.pasetoBuilderV2(null), keyProvider, tokenClass);
	}

	@Override
	public EncodingProvider encodingProvider() {
		return new JacksonJsonProvider();
	}

	@Override
	public V1CryptoProvider v1CryptoProvider() {
		return new JvmV1CryptoProvider();
	}

	@Override
	public V2CryptoProvider v2CryptoProvider() {
		return new LibSodiumV2CryptoProvider();
	}
}
