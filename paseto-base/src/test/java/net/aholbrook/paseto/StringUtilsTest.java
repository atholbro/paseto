/*
Copyright 2018 Andrew Holbrook

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package net.aholbrook.paseto;

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
		AssertUtils.assertEquals(new short[] {0xE2, 0x99, 0xA0}, StringUtils.getBytesUtf8("\u2660"));
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
