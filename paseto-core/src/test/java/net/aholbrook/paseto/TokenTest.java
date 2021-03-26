package net.aholbrook.paseto;

import net.aholbrook.paseto.data.TokenTestVectors;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.time.OffsetDateTime;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class TokenTest {
	@Test
	public void token_setNullDateTimes() {
		Token token1 = new Token();
		token1.setExpiration(null);
		token1.setIssuedAt(null);
		token1.setNotBefore(null);
	}

	@Test
	public void token_equals() {
		Token token1 = new Token()
				.setExpiration(TokenTestVectors.TOKEN_1.getExpiration())
				.setSubject(TokenTestVectors.TOKEN_1.getSubject())
				.setNotBefore(TokenTestVectors.TOKEN_1.getNotBefore())
				.setAudience(TokenTestVectors.TOKEN_1.getAudience())
				.setIssuedAt(TokenTestVectors.TOKEN_1.getIssuedAt())
				.setTokenId(TokenTestVectors.TOKEN_1.getTokenId())
				.setIssuer(TokenTestVectors.TOKEN_1.getIssuer());
		Assertions.assertEquals(token1, token1);
		Assertions.assertEquals(TokenTestVectors.TOKEN_1, token1);
		Assertions.assertEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
	}

	@Test
	public void token_notEquals_exp() {
		Token token1 = new Token()
				.setExpiration(TokenTestVectors.TOKEN_2.getExpiration())
				.setSubject(TokenTestVectors.TOKEN_1.getSubject())
				.setNotBefore(TokenTestVectors.TOKEN_1.getNotBefore())
				.setAudience(TokenTestVectors.TOKEN_1.getAudience())
				.setIssuedAt(TokenTestVectors.TOKEN_1.getIssuedAt())
				.setTokenId(TokenTestVectors.TOKEN_1.getTokenId())
				.setIssuer(TokenTestVectors.TOKEN_1.getIssuer());
		Assertions.assertNotEquals(token1, new Object());
		Assertions.assertEquals(false, token1.equals(null));
		Assertions.assertEquals(false, token1.equals(1));
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
	}

	@Test
	public void token_notEquals_sub() {
		Token token1 = new Token()
				.setExpiration(TokenTestVectors.TOKEN_1.getExpiration())
				.setSubject(TokenTestVectors.TOKEN_2.getSubject())
				.setNotBefore(TokenTestVectors.TOKEN_1.getNotBefore())
				.setAudience(TokenTestVectors.TOKEN_1.getAudience())
				.setIssuedAt(TokenTestVectors.TOKEN_1.getIssuedAt())
				.setTokenId(TokenTestVectors.TOKEN_1.getTokenId())
				.setIssuer(TokenTestVectors.TOKEN_1.getIssuer());
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
	}

	@Test
	public void token_notEquals_nbf() {
		Token token1 = new Token()
				.setExpiration(TokenTestVectors.TOKEN_1.getExpiration())
				.setSubject(TokenTestVectors.TOKEN_1.getSubject())
				.setNotBefore(TokenTestVectors.TOKEN_2.getNotBefore())
				.setAudience(TokenTestVectors.TOKEN_1.getAudience())
				.setIssuedAt(TokenTestVectors.TOKEN_1.getIssuedAt())
				.setTokenId(TokenTestVectors.TOKEN_1.getTokenId())
				.setIssuer(TokenTestVectors.TOKEN_1.getIssuer());
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
	}

	@Test
	public void token_notEquals_aud() {
		Token token1 = new Token()
				.setExpiration(TokenTestVectors.TOKEN_1.getExpiration())
				.setSubject(TokenTestVectors.TOKEN_1.getSubject())
				.setNotBefore(TokenTestVectors.TOKEN_1.getNotBefore())
				.setAudience(TokenTestVectors.TOKEN_2.getAudience())
				.setIssuedAt(TokenTestVectors.TOKEN_1.getIssuedAt())
				.setTokenId(TokenTestVectors.TOKEN_1.getTokenId())
				.setIssuer(TokenTestVectors.TOKEN_1.getIssuer());
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
	}

	@Test
	public void token_notEquals_iat() {
		Token token1 = new Token()
				.setExpiration(TokenTestVectors.TOKEN_1.getExpiration())
				.setSubject(TokenTestVectors.TOKEN_1.getSubject())
				.setNotBefore(TokenTestVectors.TOKEN_1.getNotBefore())
				.setAudience(TokenTestVectors.TOKEN_1.getAudience())
				.setIssuedAt(TokenTestVectors.TOKEN_2.getIssuedAt())
				.setTokenId(TokenTestVectors.TOKEN_1.getTokenId())
				.setIssuer(TokenTestVectors.TOKEN_1.getIssuer());
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
	}

	@Test
	public void token_notEquals_jti() {
		Token token1 = new Token()
				.setExpiration(TokenTestVectors.TOKEN_1.getExpiration())
				.setSubject(TokenTestVectors.TOKEN_1.getSubject())
				.setNotBefore(TokenTestVectors.TOKEN_1.getNotBefore())
				.setAudience(TokenTestVectors.TOKEN_1.getAudience())
				.setIssuedAt(TokenTestVectors.TOKEN_1.getIssuedAt())
				.setTokenId(TokenTestVectors.TOKEN_2.getTokenId())
				.setIssuer(TokenTestVectors.TOKEN_1.getIssuer());
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
	}

	@Test
	public void token_notEquals_iss() {
		Token token1 = new Token()
				.setExpiration(TokenTestVectors.TOKEN_1.getExpiration())
				.setSubject(TokenTestVectors.TOKEN_1.getSubject())
				.setNotBefore(TokenTestVectors.TOKEN_1.getNotBefore())
				.setAudience(TokenTestVectors.TOKEN_1.getAudience())
				.setIssuedAt(TokenTestVectors.TOKEN_1.getIssuedAt())
				.setTokenId(TokenTestVectors.TOKEN_1.getTokenId())
				.setIssuer(TokenTestVectors.TOKEN_2.getIssuer());
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assertions.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
	}

	@Test
	public void token_getExpirationWrapped() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = token.getExpirationWrapped();
		Assertions.assertEquals(TokenTestVectors.TOKEN_1.getExpiration(), time.toEpochSecond());
	}

	@Test
	public void token_getNotBeforeWrapped() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = token.getNotBeforeWrapped();
		Assertions.assertEquals(TokenTestVectors.TOKEN_1.getNotBefore(), time.toEpochSecond());
	}

	@Test
	public void token_getIssuedAtWrapped() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = token.getIssuedAtWrapped();
		Assertions.assertEquals(TokenTestVectors.TOKEN_1.getIssuedAt(), time.toEpochSecond());
	}

	@Test
	public void token_toString() {
		Token token = TokenTestVectors.TOKEN_1;
		String expected = "Token{iss='paragonie.com', sub='test', aud='pie-hosted.com', jti='87IFSGFgPNtQNNuw0AtuLttP', exp=2039-01-01T00:00Z, nbf=2038-04-01T00:00Z, iat=2038-03-17T00:00Z}";
		Assertions.assertEquals(expected, token.toString());
	}
}
