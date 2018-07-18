package net.aholbrook.paseto.test.data;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import net.aholbrook.paseto.service.Token;

import java.util.Objects;

@JsonPropertyOrder({"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "userId"})
public class CustomToken extends Token {
	private Long userId;

	public Long getUserId() {
		return userId;
	}

	public CustomToken setUserId(Long userId) {
		this.userId = userId;
		return this;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;
		CustomToken that = (CustomToken) o;
		return Objects.equals(userId, that.userId);
	}

	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), userId);
	}

	@Override
	public String toString() {
		return "CustomToken{"
				+ "userId=" + userId
				+ ", token='" + super.toString() + '\''
				+ '}';
	}
}
