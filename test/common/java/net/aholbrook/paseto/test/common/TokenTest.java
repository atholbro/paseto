package net.aholbrook.paseto.test.common;

import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.test.common.data.TokenTestVectors;
import org.junit.Assert;
import org.junit.Test;

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
		Assert.assertEquals(token1, token1);
		Assert.assertEquals(TokenTestVectors.TOKEN_1, token1);
		Assert.assertEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
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
		Assert.assertNotEquals(token1, new Object());
		Assert.assertEquals(false, token1.equals(null));
		Assert.assertEquals(false, token1.equals(1));
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
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
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
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
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
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
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
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
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
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
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
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
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1, token1);
		Assert.assertNotEquals(TokenTestVectors.TOKEN_1.hashCode(), token1.hashCode());
	}
}
