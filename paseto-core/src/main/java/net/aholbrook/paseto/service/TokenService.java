package net.aholbrook.paseto.service;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.TokenWithFooter;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.exception.claims.MissingClaimException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

public abstract class TokenService<_TokenType extends Token> {
	final Paseto paseto;
	final Class<_TokenType> tokenClass;
	final Claim[] claims;
	private final Duration defaultValidityPeriod;

	TokenService(Paseto paseto, Claim[] claims, Duration defaultValidityPeriod,
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

	abstract public <_FooterType> TokenWithFooter<_TokenType, _FooterType> decodeWithFooter(String token,
			Class<_FooterType> footerClass);

	abstract public String getFooter(String token);

	abstract public <_FooterType> _FooterType getFooter(String token, Class<_FooterType> footerClass);

	protected final void validateToken(_TokenType token) {
		// set issued at if null and we have a defaultValidityPeriod
		if (token.getIssuedAt() == null && defaultValidityPeriod != null) {
			token.setIssuedAt(OffsetDateTime.now(Clock.systemUTC()).toEpochSecond());
		}

		// set expiry if null and we have a default
		if (token.getExpiration() == null) {
			if (defaultValidityPeriod != null) {
				OffsetDateTime issuedAt = Instant.ofEpochSecond(token.getIssuedAt()).atOffset(ZoneOffset.UTC);
				token.setExpiration(issuedAt.plus(defaultValidityPeriod).toEpochSecond());
			} else {
				throw new MissingClaimException(Token.CLAIM_EXPIRATION, "TokenService", token);
			}
		}
	}
}
