package net.aholbrook.paseto.service;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.Tuple;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.Claims;

import java.time.Duration;

public class PublicTokenService<_TokenType extends Token> extends TokenService<_TokenType> {
	private final KeyProvider keyProvider;

	public PublicTokenService(Paseto<_TokenType> paseto, KeyProvider keyProvider, Class<_TokenType> tokenClass) {
		this(paseto, keyProvider, Claims.DEFAULT_CLAIM_CHECKS, null, tokenClass);
	}

	public PublicTokenService(Paseto<_TokenType> paseto, KeyProvider keyProvider, Claim[] claims,
			Class<_TokenType> tokenClass) {
		this(paseto, keyProvider, claims, null, tokenClass);
	}

	public PublicTokenService(Paseto<_TokenType> paseto, KeyProvider keyProvider, Duration defaultValidityPeriod,
			Class<_TokenType> tokenClass) {
		this(paseto, keyProvider, Claims.DEFAULT_CLAIM_CHECKS, defaultValidityPeriod, tokenClass);
	}

	public PublicTokenService(Paseto<_TokenType> paseto, KeyProvider keyProvider, Claim[] claims,
			Duration defaultValidityPeriod, Class<_TokenType> tokenClass) {
		super(paseto, claims, defaultValidityPeriod, tokenClass);
		this.keyProvider = keyProvider;
	}

	@Override
	public String encode(_TokenType token) {
		validateToken(token);
		return paseto.sign(token, keyProvider.getSecretKey());
	}

	@Override
	public <_FooterType> String encode(_TokenType token, _FooterType footer) {
		validateToken(token);
		return paseto.sign(token, keyProvider.getSecretKey(), footer);
	}

	@Override
	public _TokenType decode(String token) {
		_TokenType result = paseto.decrypt(token, keyProvider.getPublicKey(), tokenClass);
		Claims.verify(result, claims);
		return result;
	}

	@Override
	public <_FooterType> _TokenType decode(String token, _FooterType footer) {
		_TokenType result = paseto.decrypt(token, keyProvider.getPublicKey(), footer, tokenClass);
		Claims.verify(result, claims);
		return result;
	}

	@Override
	public <_FooterType> Tuple<_TokenType, _FooterType> decodeWithFooter(String token, Class<_FooterType> footerClass) {
		Tuple<_TokenType, _FooterType> result
				= paseto.decryptWithFooter(token, keyProvider.getPublicKey(), tokenClass, footerClass);
		Claims.verify(result.a, claims);
		return result;
	}

	public <_FooterType> _FooterType getFooter(String token, Class<_FooterType> footerClass) {
		return paseto.extractFooter(token, footerClass);
	}

	public interface KeyProvider {
		byte[] getSecretKey();
		byte[] getPublicKey();
	}

	public static class Builder<_TokenType extends Token> {
		private final Paseto<_TokenType> paseto;
		private final Class<_TokenType> tokenClass;
		private final KeyProvider keyProvider;
		private Duration defaultValidityPeriod = null;
		private Claim[] claims = Claims.DEFAULT_CLAIM_CHECKS;

		public Builder(Paseto<_TokenType> paseto, Class<_TokenType> tokenClass, KeyProvider keyProvider) {
			this.paseto = paseto;
			this.tokenClass = tokenClass;
			this.keyProvider = keyProvider;
		}

		public Builder<_TokenType> withDefaultValidityPeriod(Duration defaultValidityPeriod) {
			this.defaultValidityPeriod = defaultValidityPeriod;
			return this;
		}

		public Builder<_TokenType> checkClaims(Claim[] claims) {
			this.claims = claims;
			return this;
		}

		public PublicTokenService<_TokenType> build() {
			return new PublicTokenService<>(paseto, keyProvider, claims, defaultValidityPeriod, tokenClass);
		}
	}
}
