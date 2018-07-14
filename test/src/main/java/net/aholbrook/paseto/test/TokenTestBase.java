package net.aholbrook.paseto.test;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.test.data.TokenTestVectors;
import org.junit.Assert;
import org.junit.Test;

public abstract class TokenTestBase {
	protected abstract EncodingProvider getEncodingProvider();

	@Test
	public void token1_encodeDecode() {
		EncodingProvider encodingProvider = getEncodingProvider();
		String s = encodingProvider.toJson(TokenTestVectors.TOKEN_1);
		Token token2 = encodingProvider.fromJson(s, Token.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_1, token2);
	}

	@Test
	public void token1_decode() {
		EncodingProvider encodingProvider = getEncodingProvider();
		Token token = encodingProvider.fromJson(TokenTestVectors.TOKEN_1_STRING, Token.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_1, token);
	}

	@Test
	public void token2_encodeDecode() {
		EncodingProvider encodingProvider = getEncodingProvider();
		String s = encodingProvider.toJson(TokenTestVectors.TOKEN_2);
		TokenTestVectors.CustomToken token2 = encodingProvider.fromJson(s, TokenTestVectors.CustomToken.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_2, token2);
	}

	@Test
	public void token2_decode() {
		EncodingProvider encodingProvider = getEncodingProvider();
		TokenTestVectors.CustomToken token = encodingProvider.fromJson(TokenTestVectors.TOKEN_2_STRING,
				TokenTestVectors.CustomToken.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_2, token);
	}
}