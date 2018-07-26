package net.aholbrook.paseto.test;

import net.aholbrook.paseto.TokenWithFooter;
import org.junit.Assert;
import org.junit.Test;

public class TokenWithFooterTest {
	@Test
	public void tokenWithFooter_getters() {
		TokenWithFooter<String, String> twf = new TokenWithFooter<>("test", "something else");
		Assert.assertEquals("test", twf.getToken());
		Assert.assertEquals("something else", twf.getFooter());
	}

	@Test
	public void tokenWithFooter_equals() {
		TokenWithFooter<String, String> twf1 = new TokenWithFooter<>("test", "something else");
		TokenWithFooter<String, String> twf2 = new TokenWithFooter<>("test", "something else");

		Assert.assertEquals(twf1, twf1);
		Assert.assertEquals(twf1, twf2);
		Assert.assertEquals(twf1.hashCode(), twf2.hashCode());
	}

	@Test
	public void tokenWithFooter_notEquals() {
		TokenWithFooter<String, String> twf1 = new TokenWithFooter<>("test", "something else");
		TokenWithFooter<String, String> twf2 = new TokenWithFooter<>("aaaa", "bb");

		Assert.assertNotEquals(twf1, new Object());
		Assert.assertEquals(false, twf1.equals(null));
		Assert.assertEquals(false, twf1.equals(1));
		Assert.assertNotEquals(twf1, twf2);
		Assert.assertNotEquals(twf1.hashCode(), twf2.hashCode());
	}
}
