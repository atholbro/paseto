package net.aholbrook.paseto.service;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.TokenWithFooter;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.Claims;
import net.aholbrook.paseto.time.Duration;

public class LocalTokenService<_TokenType extends Token> extends TokenService<_TokenType> {
	private final KeyProvider keyProvider;

	private LocalTokenService(Paseto paseto, KeyProvider keyProvider, Claim[] claims,
			Duration defaultValidityPeriod, Class<_TokenType> tokenClass) {
		super(paseto, claims, defaultValidityPeriod, tokenClass);
		this.keyProvider = keyProvider;
	}

	@Override
	public String encode(_TokenType token) {
		validateToken(token);
		return paseto.encrypt(token, keyProvider.getSecretKey());
	}

	@Override
	public <_FooterType> String encode(_TokenType token, _FooterType footer) {
		validateToken(token);
		return paseto.encrypt(token, keyProvider.getSecretKey(), footer);
	}

	@Override
	public _TokenType decode(String token) {
		_TokenType result = paseto.decrypt(token, keyProvider.getSecretKey(), tokenClass);
		Claims.verify(result, claims);
		return result;
	}

	@Override
	public <_FooterType> _TokenType decode(String token, _FooterType footer) {
		_TokenType result = paseto.decrypt(token, keyProvider.getSecretKey(), footer, tokenClass);
		Claims.verify(result, claims);
		return result;
	}

	@Override
	public <_FooterType> TokenWithFooter<_TokenType, _FooterType> decodeWithFooter(String token, Class<_FooterType> footerClass) {
		TokenWithFooter<_TokenType, _FooterType> result
				= paseto.decryptWithFooter(token, keyProvider.getSecretKey(), tokenClass, footerClass);
		Claims.verify(result.getToken(), claims);
		return result;
	}

	@Override
	public <_FooterType> _FooterType getFooter(String token, Class<_FooterType> footerClass) {
		return paseto.extractFooter(token, footerClass);
	}

	public interface KeyProvider {
		byte[] getSecretKey();
	}

	public static class Builder<_TokenType extends Token> {
		private final Paseto paseto;
		private final Class<_TokenType> tokenClass;
		private final KeyProvider keyProvider;
		private Long defaultValidityPeriod = null;
		private Claim[] claims = Claims.DEFAULT_CLAIM_CHECKS;

		public Builder(Paseto paseto, Class<_TokenType> tokenClass, KeyProvider keyProvider) {
			this.paseto = paseto;
			this.tokenClass = tokenClass;
			this.keyProvider = keyProvider;
		}

		public Builder<_TokenType> withDefaultValidityPeriod(Long seconds) {
			this.defaultValidityPeriod = seconds;
			return this;
		}

		public Builder<_TokenType> checkClaims(Claim[] claims) {
			this.claims = claims;
			return this;
		}

		public LocalTokenService<_TokenType> build() {
			return new LocalTokenService<>(paseto,
					keyProvider,
					claims,
					defaultValidityPeriod != null ? Duration.ofSeconds(defaultValidityPeriod) : null,
					tokenClass);
		}
	}
}
