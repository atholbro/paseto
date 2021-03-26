package net.aholbrook.paseto;

import net.aholbrook.paseto.util.StringUtils;
import net.aholbrook.paseto.utils.AssertUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class StringUtilsTest {
	@Test
	public void stringUtils_ntes() {
		Assertions.assertEquals("", StringUtils.ntes(null));
		Assertions.assertEquals("", StringUtils.ntes(""));
		Assertions.assertNotEquals("", StringUtils.ntes("a"));
		Assertions.assertNotEquals("", StringUtils.ntes("testing"));
		Assertions.assertNotEquals("", StringUtils.ntes(" "));
	}

	@Test
	public void stringUtils_notEmpty() {
		Assertions.assertTrue(StringUtils.isEmpty(null));
		Assertions.assertTrue(StringUtils.isEmpty(""));
		Assertions.assertFalse(StringUtils.isEmpty("a"));
		Assertions.assertFalse(StringUtils.isEmpty("testing"));
		Assertions.assertFalse(StringUtils.isEmpty(" "));
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
		Assertions.assertEquals("", StringUtils.fromUtf8Bytes(null));
		Assertions.assertEquals("", StringUtils.fromUtf8Bytes(new byte[] {}));
		Assertions.assertEquals("A", StringUtils.fromUtf8Bytes(new byte[] {0x41}));
		Assertions.assertEquals("test", StringUtils.fromUtf8Bytes(new byte[] {0x74, 0x65, 0x73, 0x74}));
		Assertions.assertEquals("\u2660", StringUtils.fromUtf8Bytes(new byte[] {-0x1E, -0x67, -0x60}));
	}

	@Test
	public void stringUtils_isEqual() {
		// empty strings / nulls
		Assertions.assertTrue(StringUtils.isEqual("", ""));
		Assertions.assertTrue(StringUtils.isEqual(null, null));
		Assertions.assertTrue(StringUtils.isEqual(null, ""));
		Assertions.assertTrue(StringUtils.isEqual("", null));

		// equal strings
		Assertions.assertTrue(StringUtils.isEqual(" ", " "));
		Assertions.assertTrue(StringUtils.isEqual("A", "A"));
		Assertions.assertTrue(StringUtils.isEqual("test", "test"));
		Assertions.assertTrue(StringUtils.isEqual("\u2660", "\u2660"));

		// not equal
		Assertions.assertFalse(StringUtils.isEqual("  ", " "));
		Assertions.assertFalse(StringUtils.isEqual("AA", "A"));
		Assertions.assertFalse(StringUtils.isEqual("testtest", "test"));
		Assertions.assertFalse(StringUtils.isEqual("\u2660\u2660", "\u2660"));
	}
}
