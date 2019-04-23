package net.aholbrook.paseto.test.common;

import net.aholbrook.paseto.test.common.utils.AssertUtils;
import net.aholbrook.paseto.util.StringUtils;
import org.junit.Assert;
import org.junit.Test;

public class StringUtilsTest {
	@Test
	public void stringUtils_ntes() {
		Assert.assertEquals("", StringUtils.ntes(null));
		Assert.assertEquals("", StringUtils.ntes(""));
		Assert.assertNotEquals("", StringUtils.ntes("a"));
		Assert.assertNotEquals("", StringUtils.ntes("testing"));
		Assert.assertNotEquals("", StringUtils.ntes(" "));
	}

	@Test
	public void stringUtils_notEmpty() {
		Assert.assertTrue(StringUtils.isEmpty(null));
		Assert.assertTrue(StringUtils.isEmpty(""));
		Assert.assertFalse(StringUtils.isEmpty("a"));
		Assert.assertFalse(StringUtils.isEmpty("testing"));
		Assert.assertFalse(StringUtils.isEmpty(" "));
	}

	@Test
	public void stringUtils_getBytesUtf8() {
		AssertUtils.assertEquals(new byte[] {}, StringUtils.getBytesUtf8(null));
		AssertUtils.assertEquals(new byte[] {}, StringUtils.getBytesUtf8(""));
		AssertUtils.assertEquals(new byte[] {0x41}, StringUtils.getBytesUtf8("A"));
		AssertUtils.assertEquals(new byte[] {0x74, 0x65, 0x73, 0x74}, StringUtils.getBytesUtf8("test"));
		AssertUtils.assertEquals(new byte[] {-0x1E, -0x67, -0x60}, StringUtils.getBytesUtf8("\u2660"));
	}

	@Test
	public void stringUtils_fromUtf8Bytes() {
		Assert.assertEquals("", StringUtils.fromUtf8Bytes(null));
		Assert.assertEquals("", StringUtils.fromUtf8Bytes(new byte[] {}));
		Assert.assertEquals("A", StringUtils.fromUtf8Bytes(new byte[] {0x41}));
		Assert.assertEquals("test", StringUtils.fromUtf8Bytes(new byte[] {0x74, 0x65, 0x73, 0x74}));
		Assert.assertEquals("\u2660", StringUtils.fromUtf8Bytes(new byte[] {-0x1E, -0x67, -0x60}));
	}

	@Test
	public void stringUtils_isEqual() {
		// empty strings / nulls
		Assert.assertTrue(StringUtils.isEqual("", ""));
		Assert.assertTrue(StringUtils.isEqual(null, null));
		Assert.assertTrue(StringUtils.isEqual(null, ""));
		Assert.assertTrue(StringUtils.isEqual("", null));

		// equal strings
		Assert.assertTrue(StringUtils.isEqual(" ", " "));
		Assert.assertTrue(StringUtils.isEqual("A", "A"));
		Assert.assertTrue(StringUtils.isEqual("test", "test"));
		Assert.assertTrue(StringUtils.isEqual("\u2660", "\u2660"));

		// not equal
		Assert.assertFalse(StringUtils.isEqual("  ", " "));
		Assert.assertFalse(StringUtils.isEqual("AA", "A"));
		Assert.assertFalse(StringUtils.isEqual("testtest", "test"));
		Assert.assertFalse(StringUtils.isEqual("\u2660\u2660", "\u2660"));
	}
}
