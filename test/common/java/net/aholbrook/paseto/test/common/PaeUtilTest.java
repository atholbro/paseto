
package net.aholbrook.paseto.test.common;

import net.aholbrook.paseto.test.common.data.PauUtilRfcTestVectors;
import net.aholbrook.paseto.test.common.utils.AssertUtils;
import net.aholbrook.paseto.util.PaeUtil;
import net.aholbrook.paseto.util.StringUtils;
import org.junit.Test;

public class PaeUtilTest {
	@Test
	public void paeUtil_RfcVector1() {
		byte[] actual = PaeUtil.pae();
		AssertUtils.assertEquals(PauUtilRfcTestVectors.PAE_VECTOR_1, actual);
	}

	@Test
	public void paeUtil_RfcVector2() {
		byte[] actual = PaeUtil.pae(StringUtils.getBytesUtf8(""));
		AssertUtils.assertEquals(PauUtilRfcTestVectors.PAE_VECTOR_2, actual);
	}

	@Test
	public void paeUtil_RfcVector3() {
		byte[] actual = PaeUtil.pae(StringUtils.getBytesUtf8("test"));
		AssertUtils.assertEquals(PauUtilRfcTestVectors.PAE_VECTOR_3, actual);
	}

	@Test(expected = NullPointerException.class)
	public void paeUtil_RfcVector4() {
		PaeUtil.pae((byte[]) null);
	}

	@Test(expected = NullPointerException.class)
	public void paeUtil_nullPieces() {
		PaeUtil.pae((byte[][]) null);
	}
}
