package net.aholbrook.paseto.service;

import net.aholbrook.paseto.time.OffsetDateTime;
import net.aholbrook.paseto.time.format.DateTimeFormatter;
import net.aholbrook.paseto.time.temporal.ChronoUnit;

import java.util.Objects;

public class Token {
	public final static String CLAIM_ISSUER = "ISSUER";
	public final static String CLAIM_SUBJECT = "SUBJECT";
	public final static String CLAIM_AUDIENCE = "AUDIENCE";
	public final static String CLAIM_EXPIRATION = "EXPIRATION";
	public final static String CLAIM_NOT_BEFORE = "NOT_BEFORE";
	public final static String CLAIM_ISSUED_AT = "ISSUED_AT";
	public final static String CLAIM_TOKEN_ID = "TOKEN_ID";

	public final static DateTimeFormatter DATETIME_FORMATTER = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ssxxxxx");

	// These are the standard names from the RFC. Using these names should lead to correct serialization with GSON.
	// Jackson requires the use of a mixin since it reads the getters/setters.
	private String iss; // Issuer
	private String sub; // Subject
	private String aud; // Audience
	private String jti; // Token Id
	private OffsetDateTime exp; // Expiration
	private OffsetDateTime nbf; // Not Before
	private OffsetDateTime iat; // Issued At

	public String getIssuer() {
		return iss;
	}

	public Token setIssuer(String issuer) {
		this.iss = issuer;
		return this;
	}

	public String getSubject() {
		return sub;
	}

	public Token setSubject(String subject) {
		this.sub = subject;
		return this;
	}

	public String getAudience() {
		return aud;
	}

	public Token setAudience(String audience) {
		this.aud = audience;
		return this;
	}

	public String getTokenId() {
		return jti;
	}

	public Token setTokenId(String tokenId) {
		this.jti = tokenId;
		return this;
	}

	public Long getExpiration() {
		return exp != null ? exp.toEpochSecond() : null;
	}

	public Token setExpiration(Long expiration) {
		this.exp = expiration != null ? OffsetDateTime.ofEpochSecond(expiration) : null;

		// Cut off mills/nanos. The formatter does this too, but only after output.
		if (this.exp != null) {
			this.exp = this.exp.truncatedTo(ChronoUnit.SECONDS);
		}

		return this;
	}

	public Long getNotBefore() {
		return nbf != null ? nbf.toEpochSecond() : null;
	}

	public Token setNotBefore(Long notBefore) {
		this.nbf = notBefore != null ? OffsetDateTime.ofEpochSecond(notBefore) : null;

		// Cut off mills/nanos. The formatter does this too, but only after output.
		if (this.nbf != null) {
			this.nbf = this.nbf.truncatedTo(ChronoUnit.SECONDS);
		}

		return this;
	}

	public Long getIssuedAt() {
		return iat != null ? iat.toEpochSecond() : null;
	}

	public Token setIssuedAt(Long issuedAt) {
		this.iat = issuedAt != null ? OffsetDateTime.ofEpochSecond(issuedAt) : null;

		// Cut off mills/nanos. The formatter does this too, but only after output.
		if (this.iat != null) {
			this.iat = this.iat.truncatedTo(ChronoUnit.SECONDS);
		}

		return this;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Token token = (Token) o;
		return Objects.equals(iss, token.iss) &&
				Objects.equals(sub, token.sub) &&
				Objects.equals(aud, token.aud) &&
				Objects.equals(jti, token.jti) &&
				Objects.equals(exp, token.exp) &&
				Objects.equals(nbf, token.nbf) &&
				Objects.equals(iat, token.iat);
	}

	@Override
	public int hashCode() {
		return Objects.hash(iss, sub, aud, jti, exp, nbf, iat);
	}

	@Override
	public String toString() {
		return "Token{" +
				"iss='" + iss + '\'' +
				", sub='" + sub + '\'' +
				", aud='" + aud + '\'' +
				", jti='" + jti + '\'' +
				", exp=" + exp +
				", nbf=" + nbf +
				", iat=" + iat +
				'}';
	}
}
