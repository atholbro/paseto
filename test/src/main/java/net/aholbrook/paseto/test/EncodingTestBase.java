package net.aholbrook.paseto.test;

import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.test.data.CustomToken;
import net.aholbrook.paseto.test.data.TokenTestVectors;
import org.junit.Assert;
import org.junit.Test;

public abstract class EncodingTestBase {
	protected abstract EncodingProvider getEncodingProvider();

	// Basic json encode & decode test.
	@Test
	public void token_encodeDecode1() {
		EncodingProvider encodingProvider = getEncodingProvider();
		String s = encodingProvider.toJson(TokenTestVectors.TOKEN_1);
		Token token2 = encodingProvider.fromJson(s, Token.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_1, token2);
	}

	// Basic json decode test.
	@Test
	public void token_decode1() {
		EncodingProvider encodingProvider = getEncodingProvider();
		Token token = encodingProvider.fromJson(TokenTestVectors.TOKEN_1_STRING, Token.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_1, token);
	}

	// Basic json encode & decode test.
	@Test
	public void token_encodeDecode2() {
		EncodingProvider encodingProvider = getEncodingProvider();
		String s = encodingProvider.toJson(TokenTestVectors.TOKEN_2);
		CustomToken token2 = encodingProvider.fromJson(s, CustomToken.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_2, token2);
	}

	// Basic json decode test.
	@Test
	public void token_decode2() {
		EncodingProvider encodingProvider = getEncodingProvider();
		CustomToken token = encodingProvider.fromJson(TokenTestVectors.TOKEN_2_STRING,
				CustomToken.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_2, token);
	}
}