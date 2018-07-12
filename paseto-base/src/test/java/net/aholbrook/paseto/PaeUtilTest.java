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

import net.aholbrook.paseto.data.PauUtilRfcTestVectors;
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
}
