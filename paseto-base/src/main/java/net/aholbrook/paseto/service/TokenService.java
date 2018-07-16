package net.aholbrook.paseto.service;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.Tuple;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.Claims;
import net.aholbrook.paseto.exception.claims.MissingClaimException;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;

abstract class TokenService<_TokenType extends Token> {
	final Paseto<_TokenType> paseto;
	final Class<_TokenType> tokenClass;
	final Claim[] claims;
	private final Duration defaultValidityPeriod;

	TokenService(Paseto<_TokenType> paseto, Claim[] claims, Class<_TokenType> tokenClass) {
		this(paseto, claims, null, tokenClass);
	}

	TokenService(Paseto<_TokenType> paseto, Duration defaultValidityPeriod, Class<_TokenType> tokenClass) {
		this(paseto, Claims.DEFAULT_CLAIM_CHECKS, defaultValidityPeriod, tokenClass);
	}

	TokenService(Paseto<_TokenType> paseto, Claim[] claims, Duration defaultValidityPeriod,
			Class<_TokenType> tokenClass) {
		this.paseto = paseto;
		this.tokenClass = tokenClass;
		this.defaultValidityPeriod = defaultValidityPeriod;
		this.claims = claims;
	}

	abstract public String encode(_TokenType token);
	abstract public <_FooterType> String encode(_TokenType token, _FooterType footer);

	abstract public _TokenType decode(String token);
	abstract public <_FooterType> _TokenType decode(String token, _FooterType footer);
	abstract public <_FooterType> Tuple<_TokenType, _FooterType> decodeWithFooter(String token,
			Class<_FooterType> footerClass);

	abstract public <_FooterType> _FooterType getFooter(String token, Class<_FooterType> footerClass);

	protected final void validateToken(_TokenType token) {
		// set issued at if null
		if (token.getIssuedAt() == null) {
			token.setIssuedAt(OffsetDateTime.now(Clock.systemUTC()));
		}

		// set expiry if null and we have a default
		if (token.getExpiration() == null) {
			if (defaultValidityPeriod != null) {
				token.setExpiration(token.getIssuedAt().plus(defaultValidityPeriod));
			} else {
				throw new MissingClaimException(Token.CLAIM_EXPIRATION, "TokenService", token);
			}
		}
	}
}
