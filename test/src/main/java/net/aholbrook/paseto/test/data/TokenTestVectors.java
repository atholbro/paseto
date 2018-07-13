package net.aholbrook.paseto.test.data;

import net.aholbrook.paseto.Token;

import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;

public class TokenTestVectors {

	public final static Token TOKEN_1 = new Token()
			.setIssuer("paragonie.com")
			.setSubject("test")
			.setAudience("pie-hosted.com")
			.setExpiration(OffsetDateTime.of(LocalDate.of(2039, 1, 1),
				LocalTime.of(0, 0, 0), ZoneOffset.UTC))
			.setNotBefore(OffsetDateTime.of(LocalDate.of(2038, 4, 1),
				LocalTime.of(0, 0, 0), ZoneOffset.UTC))
			.setIssuedAt(OffsetDateTime.of(LocalDate.of(2038, 3, 17),
				LocalTime.of(0, 0, 0), ZoneOffset.UTC))
			.setTokenId("87IFSGFgPNtQNNuw0AtuLttP");
	public final static String TOKEN_1_STRING = "{\"exp\":\"2039-01-01T00:00:00+00:00\",\"iss\":\"paragonie.com\","
			+ "\"sub\":\"test\",\"aud\":\"pie-hosted.com\",\"jti\":\"87IFSGFgPNtQNNuw0AtuLttP\","
			+ "\"nbf\":\"2038-04-01T00:00:00+00:00\",\"iat\":\"2038-03-17T00:00:00+00:00\"}";

	public final static Token TOKEN_2 = new CustomToken()
			.setUserId(100L)
			.setIssuer("auth.example.com")
			.setSubject("user-auth")
			.setAudience("internal-service.example.com")
			.setExpiration(OffsetDateTime.of(LocalDate.of(2018, 1, 1),
					LocalTime.of(17, 23, 44), ZoneOffset.UTC))
			.setIssuedAt(OffsetDateTime.of(LocalDate.of(2018, 1, 1),
					LocalTime.of(17, 18, 44), ZoneOffset.UTC))
			.setNotBefore(OffsetDateTime.of(LocalDate.of(2018, 1, 1),
					LocalTime.of(17, 18, 44), ZoneOffset.UTC));
	public final static String TOKEN_2_STRING = "{\"userId\":100,\"exp\":\"2018-01-01T17:23:44+00:00\","
			+ "\"sub\":\"user-auth\",\"iss\":\"auth.example.com\",\"aud\":\"internal-service.example.com\","
			+ "\"jti\":null,\"nbf\":\"2018-01-01T17:18:44+00:00\",\"iat\":\"2018-01-01T17:18:44+00:00\"}";

	public static class CustomToken extends Token {
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
}
