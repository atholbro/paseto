package net.aholbrook.paseto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class TokenWithFooterTest {
	@Test
	public void tokenWithFooter_getters() {
		TokenWithFooter<String, String> twf = new TokenWithFooter<>("test", "something else");
		Assertions.assertEquals("test", twf.getToken());
		Assertions.assertEquals("something else", twf.getFooter());
	}

	@Test
	public void tokenWithFooter_equals() {
		TokenWithFooter<String, String> twf1 = new TokenWithFooter<>("test", "something else");
		TokenWithFooter<String, String> twf2 = new TokenWithFooter<>("test", "something else");

		Assertions.assertEquals(twf1, twf1);
		Assertions.assertEquals(twf1, twf2);
		Assertions.assertEquals(twf1.hashCode(), twf2.hashCode());
	}

	@Test
	public void tokenWithFooter_notEquals() {
		TokenWithFooter<String, String> twf1 = new TokenWithFooter<>("test", "something else");
		TokenWithFooter<String, String> twf2 = new TokenWithFooter<>("aaaa", "something else");
		TokenWithFooter<String, String> twf3 = new TokenWithFooter<>("test", "bb");

		Assertions.assertNotEquals(twf1, new Object());
		Assertions.assertEquals(false, twf1.equals(null));
		Assertions.assertEquals(false, twf1.equals(1));
		Assertions.assertNotEquals(twf1, twf2);
		Assertions.assertNotEquals(twf1.hashCode(), twf2.hashCode());

		Assertions.assertNotEquals(twf1, twf3);
		Assertions.assertNotEquals(twf1.hashCode(), twf3.hashCode());
	}
}
