package net.aholbrook.paseto.encoding.json.jackson.mixin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.time.OffsetDateTime;

@JsonPropertyOrder({"iss", "sub", "aud", "exp", "nbf", "iat", "jti"})
public abstract class TokenMixIn {
	@JsonProperty("iss")
	abstract String getIssuer();

	@JsonProperty("iss")
	abstract void setIssuer(String issuer);

	@JsonProperty("sub")
	abstract String getSubject();

	@JsonProperty("sub")
	abstract void setSubject(String subject);

	@JsonProperty("aud")
	abstract String getAudience();

	@JsonProperty("aud")
	abstract void setAudience(String audience);

	@JsonProperty("jti")
	abstract String getTokenId();

	@JsonProperty("jti")
	abstract void setTokenId(String tokenId);

	@JsonProperty("exp")
	abstract OffsetDateTime getExpiration();

	@JsonProperty("exp")
	abstract void setExpiration(OffsetDateTime expiration);

	@JsonProperty("nbf")
	abstract OffsetDateTime getNotBefore();

	@JsonProperty("nbf")
	abstract void setNotBefore(OffsetDateTime notBefore);

	@JsonProperty("iat")
	abstract OffsetDateTime getIssuedAt();

	@JsonProperty("iat")
	abstract void setIssuedAt(OffsetDateTime issuedAt);
}
