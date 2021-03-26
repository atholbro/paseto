package net.aholbrook.paseto;

import net.aholbrook.paseto.util.ByteArrayUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ByteArrayUtilsTest {
	@Test
	public void byteArrayUtils_isEqual() {
		// empty strings / nulls
		Assertions.assertTrue(ByteArrayUtils.isEqual(new byte[] {}, new byte[] {}));

		// equal
		Assertions.assertTrue(ByteArrayUtils.isEqual(new byte[] {0x01}, new byte[] {0x01}));
		Assertions.assertTrue(ByteArrayUtils.isEqual(new byte[] {0x01, 0x02}, new byte[] {0x01, 0x02}));
		Assertions.assertTrue(ByteArrayUtils.isEqual(new byte[] {0x01, 0x50}, new byte[] {0x01, 0x50}));

		// not equal
		Assertions.assertFalse(ByteArrayUtils.isEqual(new byte[] {0x01}, new byte[] {0x02}));
		Assertions.assertFalse(ByteArrayUtils.isEqual(new byte[] {0x01, 0x02}, new byte[] {0x02, 0x01}));
		Assertions.assertFalse(ByteArrayUtils.isEqual(new byte[] {0x01, 0x50}, new byte[] {0x50, 0x50}));
	}
}
