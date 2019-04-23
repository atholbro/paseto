package net.aholbrook.paseto.test.common;

import net.aholbrook.paseto.util.ByteArrayUtils;
import org.junit.Assert;
import org.junit.Test;

public class ByteArrayUtilsTest {
	@Test
	public void byteArrayUtils_isEqual() {
		// empty strings / nulls
		Assert.assertTrue(ByteArrayUtils.isEqual(new byte[] {}, new byte[] {}));

		// equal
		Assert.assertTrue(ByteArrayUtils.isEqual(new byte[] {0x01}, new byte[] {0x01}));
		Assert.assertTrue(ByteArrayUtils.isEqual(new byte[] {0x01, 0x02}, new byte[] {0x01, 0x02}));
		Assert.assertTrue(ByteArrayUtils.isEqual(new byte[] {0x01, 0x50}, new byte[] {0x01, 0x50}));

		// not equal
		Assert.assertFalse(ByteArrayUtils.isEqual(new byte[] {0x01}, new byte[] {0x02}));
		Assert.assertFalse(ByteArrayUtils.isEqual(new byte[] {0x01, 0x02}, new byte[] {0x02, 0x01}));
		Assert.assertFalse(ByteArrayUtils.isEqual(new byte[] {0x01, 0x50}, new byte[] {0x50, 0x50}));
	}
}
