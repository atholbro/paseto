
package net.aholbrook.paseto;

import net.aholbrook.paseto.data.PauUtilRfcTestVectors;
import net.aholbrook.paseto.util.PaeUtil;
import net.aholbrook.paseto.util.StringUtils;
import net.aholbrook.paseto.utils.AssertUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PAE Util")
public class PaeUtilTest {
	@Test
	@DisplayName("PAE Util produces correct result for test vector 1.")
	public void paeUtil_RfcVector1() {
		byte[] actual = PaeUtil.pae();
		AssertUtils.assertEquals(PauUtilRfcTestVectors.PAE_VECTOR_1, actual);
	}

	@Test
	@DisplayName("PAE Util produces correct result for test vector 2.")
	public void paeUtil_RfcVector2() {
		byte[] actual = PaeUtil.pae(StringUtils.getBytesUtf8(""));
		AssertUtils.assertEquals(PauUtilRfcTestVectors.PAE_VECTOR_2, actual);
	}

	@Test
	@DisplayName("PAE Util produces correct result for test vector 1.")
	public void paeUtil_RfcVector3() {
		byte[] actual = PaeUtil.pae(StringUtils.getBytesUtf8("test"));
		AssertUtils.assertEquals(PauUtilRfcTestVectors.PAE_VECTOR_3, actual);
	}

	@Test
	@DisplayName("PAE Util throws NullPointerException if given null input.")
	public void paeUtil_RfcVector4() {
		Assertions.assertThrows(NullPointerException.class, () -> PaeUtil.pae((byte[]) null));
	}

	@Test
	@DisplayName("PAE Util throws NullPointerException if given null input (as a 2D array).")
	public void paeUtil_nullPieces() {
		Assertions.assertThrows(NullPointerException.class, () -> PaeUtil.pae((byte[][]) null));
	}
}
