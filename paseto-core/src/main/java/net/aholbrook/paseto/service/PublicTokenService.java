package net.aholbrook.paseto.service;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.PasetoV1;
import net.aholbrook.paseto.PasetoV2;
import net.aholbrook.paseto.TokenWithFooter;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.Claims;
import net.aholbrook.paseto.keys.AsymmetricPublicKey;
import net.aholbrook.paseto.keys.AsymmetricSecretKey;
import net.aholbrook.paseto.time.Duration;


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
		AsymmetricSecretKey getSecretKey();

		AsymmetricPublicKey getPublicKey();
	}

	public static class Builder<_TokenType extends Token> {
		private final Class<_TokenType> tokenClass;
		private final KeyProvider keyProvider;
		private Paseto paseto;
		private Long defaultValidityPeriod = null;
		private Claim[] claims = Claims.DEFAULT_CLAIM_CHECKS;

		public Builder(Class<_TokenType> tokenClass, KeyProvider keyProvider) {
			this.tokenClass = tokenClass;
			this.keyProvider = keyProvider;
		}

		public Builder<_TokenType> withV1() {
			this.paseto = new PasetoV1.Builder().build();
			return this;
		}

		public Builder<_TokenType> withV2() {
			this.paseto = new PasetoV2.Builder().build();
			return this;
		}

		public Builder<_TokenType> withPaseto(Paseto paseto) {
			this.paseto = paseto;
			return this;
		}

		public Builder<_TokenType> withDefaultValidityPeriod(Long defaultValidityPeriod) {
			this.defaultValidityPeriod = defaultValidityPeriod;
			return this;
		}

		public Builder<_TokenType> checkClaims(Claim[] claims) {
			this.claims = claims;
			return this;
		}

		public PublicTokenService<_TokenType> build() {
			if (paseto == null) { withV2(); }

			return new PublicTokenService<>(paseto,
					keyProvider,
					claims,
					defaultValidityPeriod != null ? Duration.ofSeconds(defaultValidityPeriod) : null,
					tokenClass);
		}
	}
}
