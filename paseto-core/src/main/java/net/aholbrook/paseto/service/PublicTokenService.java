package net.aholbrook.paseto.service;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.TokenWithFooter;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.Claims;

import java.time.Duration;

public class PublicTokenService<_TokenType extends Token> extends TokenService<_TokenType> {
	private final KeyProvider keyProvider;

	private PublicTokenService(Paseto paseto, KeyProvider keyProvider, Claim[] claims,
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
		_TokenType result = paseto.verify(token, keyProvider.getPublicKey(), tokenClass);
		Claims.verify(result, claims);
		return result;
	}

	@Override
	public <_FooterType> _TokenType decode(String token, _FooterType footer) {
		_TokenType result = paseto.verify(token, keyProvider.getPublicKey(), footer, tokenClass);
		Claims.verify(result, claims);
		return result;
	}

	@Override
	public <_FooterType> TokenWithFooter<_TokenType, _FooterType> decodeWithFooter(String token,
			Class<_FooterType> footerClass) {
		TokenWithFooter<_TokenType, _FooterType> result
				= paseto.verifyWithFooter(token, keyProvider.getPublicKey(), tokenClass, footerClass);
		Claims.verify(result.getToken(), claims);
		return result;
	}

	public String getFooter(String token) {
		return paseto.extractFooter(token);
	}

	public <_FooterType> _FooterType getFooter(String token, Class<_FooterType> footerClass) {
		return paseto.extractFooter(token, footerClass);
	}

	public interface KeyProvider {
		byte[] getSecretKey();

		byte[] getPublicKey();
	}

	public static class Builder<_TokenType extends Token> {
		private final Paseto paseto;
		private final Class<_TokenType> tokenClass;
		private final KeyProvider keyProvider;
		private Duration defaultValidityPeriod = null;
		private Claim[] claims = Claims.DEFAULT_CLAIM_CHECKS;

		public Builder(Paseto paseto, Class<_TokenType> tokenClass, KeyProvider keyProvider) {
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
