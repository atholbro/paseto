package net.aholbrook.paseto.test.common;

import net.aholbrook.paseto.encoding.EncodingLoader;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.encoding.exception.EncodingException;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.test.common.data.CustomToken;
import net.aholbrook.paseto.test.common.data.TokenTestVectors;
import org.junit.Assert;
import org.junit.Test;

public class EncodingTest {
	private static EncodingProvider encodingProvider() {
		return EncodingLoader.getProvider();
	}

	// Basic json encode & decode test.
	@Test
	public void token_encodeDecode1() {
		EncodingProvider encodingProvider = encodingProvider();
		String s = encodingProvider.encode(TokenTestVectors.TOKEN_1);
		Token token2 = encodingProvider.decode(s, Token.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_1, token2);
	}

	// Basic json decode test.
	@Test
	public void token_decode1() {
		EncodingProvider encodingProvider = encodingProvider();
		Token token = encodingProvider.decode(TokenTestVectors.TOKEN_1_STRING, Token.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_1, token);
	}

	// Basic json encode & decode test.
	@Test
	public void token_encodeDecode2() {
		EncodingProvider encodingProvider = encodingProvider();
		String s = encodingProvider.encode(TokenTestVectors.TOKEN_2);
		CustomToken token2 = encodingProvider.decode(s, CustomToken.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_2, token2);
	}

	// Basic json decode test.
	@Test
	public void token_decode2() {
		EncodingProvider encodingProvider = encodingProvider();
		CustomToken token = encodingProvider.decode(TokenTestVectors.TOKEN_2_STRING,
				CustomToken.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_2, token);
	}

	// encode / decode errors
	@Test
	public void token_encodeNull() {
		EncodingProvider encodingProvider = encodingProvider();

		String s = encodingProvider.encode(null);
		Assert.assertNull(s);
	}

	@Test
	public void token_decodeNull() {
		EncodingProvider encodingProvider = encodingProvider();
		Token token = encodingProvider.decode(null, Token.class);
		Assert.assertNull(token);
	}

	@Test(expected = EncodingException.class)
	public void token_decodeEmpty() {
		EncodingProvider encodingProvider = encodingProvider();
		Token token = encodingProvider.decode("", Token.class);
	}

	@Test(expected = EncodingException.class)
	public void token_decodeError() {
		EncodingProvider encodingProvider = encodingProvider();
		Token token = encodingProvider.decode("notjson", Token.class);
	}
}