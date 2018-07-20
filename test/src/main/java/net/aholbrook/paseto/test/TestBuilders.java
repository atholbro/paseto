package net.aholbrook.paseto.test;


import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.crypto.v1.V1CryptoProvider;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.service.LocalTokenService;
import net.aholbrook.paseto.service.PublicTokenService;
import net.aholbrook.paseto.service.Token;

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
}
