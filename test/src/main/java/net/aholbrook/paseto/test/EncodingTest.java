package net.aholbrook.paseto.test;

import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.encoding.exception.EncodingException;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.test.data.CustomToken;
import net.aholbrook.paseto.test.data.TokenTestVectors;
import net.aholbrook.paseto.test.utils.TestContext;
import net.aholbrook.paseto.time.OffsetDateTime;
import org.junit.Assert;
import org.junit.Test;

import java.util.Objects;

public class EncodingTest {
	// Basic json encode & decode test.
	@Test
	public void token_encodeDecode1() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();
		String s = encodingProvider.encode(TokenTestVectors.TOKEN_1);
		Token token2 = encodingProvider.decode(s, Token.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_1, token2);
	}

	// Basic json decode test.
	@Test
	public void token_decode1() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();
		Token token = encodingProvider.decode(TokenTestVectors.TOKEN_1_STRING, Token.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_1, token);
	}

	// Basic json encode & decode test.
	@Test
	public void token_encodeDecode2() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();
		String s = encodingProvider.encode(TokenTestVectors.TOKEN_2);
		CustomToken token2 = encodingProvider.decode(s, CustomToken.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_2, token2);
	}

	// Basic json decode test.
	@Test
	public void token_decode2() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();
		CustomToken token = encodingProvider.decode(TokenTestVectors.TOKEN_2_STRING,
				CustomToken.class);
		Assert.assertEquals("decoded token", TokenTestVectors.TOKEN_2, token);
	}

	// encode / decode errors
	@Test
	public void token_encodeNull() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();

		String s = encodingProvider.encode(null);
		Assert.assertNull(s);
	}

	// encode a type which throws an exception, should result in an EncodingException.
	@Test(expected = EncodingException.class)
	public void token_encodeError() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();

		encodingProvider.encode(new BrokenType());
	}

	@Test
	public void token_decodeNull() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();
		Token token = encodingProvider.decode(null, Token.class);
		Assert.assertNull(token);
	}

	@Test(expected = EncodingException.class)
	public void token_decodeEmpty() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();
		Token token = encodingProvider.decode("", Token.class);
	}

	@Test(expected = EncodingException.class)
	public void token_decodeError() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();
		Token token = encodingProvider.decode("notjson", Token.class);
	}

	private static class BrokenType {
		public String getName() {
			throw new NullPointerException();
		}
	}
}