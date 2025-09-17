package net.aholbrook.paseto.service;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.PasetoV1;
import net.aholbrook.paseto.PasetoV2;
import net.aholbrook.paseto.PasetoV4;
import net.aholbrook.paseto.TokenWithFooter;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.Claims;
import net.aholbrook.paseto.keys.SymmetricKey;

import java.time.Duration;

public class LocalTokenService<_TokenType extends Token> extends TokenService<_TokenType> {
	private final KeyProvider keyProvider;

	private LocalTokenService(Paseto paseto, KeyProvider keyProvider, Claim[] claims,
			Duration defaultValidityPeriod, Class<_TokenType> tokenClass, boolean allowTokensWithoutExpiration) {
		super(paseto, claims, defaultValidityPeriod, tokenClass, allowTokensWithoutExpiration);
		this.keyProvider = keyProvider;
	}

	@Override
	public String encode(_TokenType token) {
		validateToken(token);
		return paseto.encrypt(token, keyProvider.getKey());
	}

	@Override
	public String encode(_TokenType token, String implicitAssertion) {
		validateToken(token);
		return paseto.encrypt(token, keyProvider.getKey(), null, implicitAssertion);
	}

	@Override
	public <_FooterType> String encode(_TokenType token, _FooterType footer) {
		validateToken(token);
		return paseto.encrypt(token, keyProvider.getKey(), footer);
	}

	@Override
	public <_FooterType> String encode(_TokenType token, _FooterType footer, String implicitAssertion) {
		validateToken(token);
		return paseto.encrypt(token, keyProvider.getKey(), footer, implicitAssertion);
	}

	@Override
	public _TokenType decode(String token) {
		_TokenType result = paseto.decrypt(token, keyProvider.getKey(), tokenClass);
		Claims.verify(result, claims);
		return result;
	}

	@Override
	public _TokenType decode(String token, String implicitAssertion) {
		_TokenType result = paseto.decrypt(token, keyProvider.getKey(), null, tokenClass, implicitAssertion);
		Claims.verify(result, claims);
		return result;
	}

	@Override
	public <_FooterType> _TokenType decode(String token, _FooterType footer) {
		_TokenType result = paseto.decrypt(token, keyProvider.getKey(), footer, tokenClass);
		Claims.verify(result, claims);
		return result;
	}

	@Override
	public <_FooterType> _TokenType decode(String token, _FooterType footer, String implicitAssertion) {
		_TokenType result = paseto.decrypt(token, keyProvider.getKey(), footer, tokenClass, implicitAssertion);
		Claims.verify(result, claims);
		return result;
	}

	@Override
	public <_FooterType> TokenWithFooter<_TokenType, _FooterType> decodeWithFooter(String token, Class<_FooterType> footerClass) {
		TokenWithFooter<_TokenType, _FooterType> result
				= paseto.decryptWithFooter(token, keyProvider.getKey(), tokenClass, footerClass);
		Claims.verify(result.getToken(), claims);
		return result;
	}

	@Override
	public <_FooterType> TokenWithFooter<_TokenType, _FooterType> decodeWithFooter(String token, Class<_FooterType> footerClass, String implicitAssertion) {
		TokenWithFooter<_TokenType, _FooterType> result
				= paseto.decryptWithFooter(token, keyProvider.getKey(), tokenClass, footerClass, implicitAssertion);
		Claims.verify(result.getToken(), claims);
		return result;
	}

	@Override
	public String getFooter(String token) {
		return paseto.extractFooter(token);
	}

	@Override
	public <_FooterType> _FooterType getFooter(String token, Class<_FooterType> footerClass) {
		return paseto.extractFooter(token, footerClass);
	}

	public interface KeyProvider {
		SymmetricKey getKey();
	}

	public static class Builder<_TokenType extends Token> {
		private final Class<_TokenType> tokenClass;
		private final KeyProvider keyProvider;
		private Paseto paseto;
		private Long defaultValidityPeriod = null;
		private Claim[] claims = Claims.DEFAULT_CLAIM_CHECKS;
		private boolean allowTokensWithoutExpiration = false;

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

		public Builder<_TokenType> withV4() {
			this.paseto = new PasetoV4.Builder().build();
			return this;
		}

		public Builder<_TokenType> withPaseto(Paseto paseto) {
			this.paseto = paseto;
			return this;
		}

		public Builder<_TokenType> withDefaultValidityPeriod(Long seconds) {
			this.defaultValidityPeriod = seconds;
			return this;
		}

		public Builder<_TokenType> withoutExpiration() {
			this.allowTokensWithoutExpiration = true;

			if (claims == Claims.DEFAULT_CLAIM_CHECKS) {
				claims = Claims.DEFAULT_NO_EXPIRY_CLAIM_CHECKS;
			}

			return this;
		}

		public Builder<_TokenType> checkClaims(Claim[] claims) {
			this.claims = claims;
			return this;
		}

		public LocalTokenService<_TokenType> build() {
			if (paseto == null) { withV2(); }

			return new LocalTokenService<>(paseto,
					keyProvider,
					claims,
					defaultValidityPeriod != null ? Duration.ofSeconds(defaultValidityPeriod) : null,
					tokenClass,
					allowTokensWithoutExpiration);
		}
	}
}
