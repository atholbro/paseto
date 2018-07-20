package net.aholbrook.paseto.test;

import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.encoding.exception.EncodingException;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.test.data.CustomToken;
import net.aholbrook.paseto.test.data.TokenTestVectors;
import org.junit.Assert;
import org.junit.Test;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.Map;
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

	// Encode date, ensure correct format
	@Test
	public void token_encodeDateTime() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();

		// 2039-01-01T00:00:00+00:00
		OffsetDateTime time = TokenTestVectors.TV_1_V1_LOCAL.getPayload().getExpiration();
		DateTimeTest test = new DateTimeTest();
		test.setExp(time);

		String s = encodingProvider.encode(test);
		Assert.assertEquals("encoded date time", "{\"exp\":\"2039-01-01T00:00:00+00:00\"}", s);
	}

	@Test
	public void token_decodeDateTime() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();

		// 2039-01-01T00:00:00+00:00
		OffsetDateTime time = TokenTestVectors.TV_1_V1_LOCAL.getPayload().getExpiration();
		DateTimeTest test = new DateTimeTest();
		test.setExp(time);

		DateTimeTest decoded = encodingProvider.decode("{\"exp\":\"2039-01-01T00:00:00+00:00\"}", DateTimeTest.class);
		Assert.assertEquals("decoded date time", test, decoded);
	}

	@Test
	public void token_encodeDateTimeNull() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();

		DateTimeTest test = new DateTimeTest();
		String s = encodingProvider.encode(test);
		Assert.assertEquals("encoded date time", "{}", s);
	}

	@Test
	public void token_decodeDateTimeNull() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();

		DateTimeTest test = new DateTimeTest();

		DateTimeTest decoded = encodingProvider.decode("{\"exp\":null}", DateTimeTest.class);
		Assert.assertEquals("decoded date time", test, decoded);
	}

	@Test
	public void token_decodeDateTimeMissing() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();

		DateTimeTest test = new DateTimeTest();

		DateTimeTest decoded = encodingProvider.decode("{}", DateTimeTest.class);
		Assert.assertEquals("decoded date time", test, decoded);
	}

	// encode / decode errors
	@Test
	public void token_encodeNull() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();

		String s = encodingProvider.encode(null);
		Assert.assertNull(s);
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

	@Test
	public void token_decodeDateTimeWrongType() {
		EncodingProvider encodingProvider = TestContext.builders().encodingProvider();

		DateTimeTest test = new DateTimeTest();

		DateTimeTest decoded = encodingProvider.decode("{\"exp\":10000}", DateTimeTest.class);
		Assert.assertEquals("decoded date time", test, decoded);
	}

	private static class DateTimeTest {
		private OffsetDateTime exp;

		public OffsetDateTime getExp() {
			return exp;
		}

		public void setExp(OffsetDateTime exp) {
			this.exp = exp;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;
			DateTimeTest that = (DateTimeTest) o;
			return Objects.equals(exp, that.exp);
		}

		@Override
		public int hashCode() {

			return Objects.hash(exp);
		}
	}
}