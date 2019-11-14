package net.aholbrook.paseto.encoding.json.jackson.mixin;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import net.aholbrook.paseto.encoding.json.jackson.TimeDeserializer;
import net.aholbrook.paseto.encoding.json.jackson.TimeSerializer;
import net.aholbrook.paseto.time.OffsetDateTime;

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
	@JsonSerialize(using = TimeSerializer.class)
	abstract Long getExpiration();

	@JsonProperty("exp")
	@JsonDeserialize(using = TimeDeserializer.class)
	abstract void setExpiration(Long expiration);

	@JsonProperty("nbf")
	@JsonSerialize(using = TimeSerializer.class)
	abstract Long getNotBefore();

	@JsonProperty("nbf")
	@JsonDeserialize(using = TimeDeserializer.class)
	abstract void setNotBefore(Long notBefore);

	@JsonProperty("iat")
	@JsonSerialize(using = TimeSerializer.class)
	abstract Long getIssuedAt();

	@JsonProperty("iat")
	@JsonDeserialize(using = TimeDeserializer.class)
	abstract void setIssuedAt(Long issuedAt);

	@JsonIgnore
	abstract OffsetDateTime getExpirationWrapped();

	@JsonIgnore
	abstract OffsetDateTime getNotBeforeWrapped();

	@JsonIgnore
	abstract OffsetDateTime getIssuedAtWrapped();
}
