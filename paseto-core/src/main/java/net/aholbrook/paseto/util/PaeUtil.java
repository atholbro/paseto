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

package net.aholbrook.paseto.util;

public class PaeUtil {
	private PaeUtil() {}

	private static byte[] le64(long n) {
		byte[] result = new byte[8];
		for (int i = 0; i < 8; ++i) {
			if (i == 7) {
				n &= 127;
			}

			result[i] = (byte) (n & 255);
			n = n >> 8;
		}

		return result;
	}

	private static int paeLen(byte[]... pieces) {
		int len = 8 + 8 * pieces.length;
		for (int i = 0; i < pieces.length; ++i) {
			len += pieces[i].length;
		}
		return len;
	}

	public static byte[] pae(byte[]... pieces) {
		if (pieces == null) { throw new NullPointerException(); }

		byte[] result = new byte[paeLen(pieces)];
		int resultPos = 0;
		System.arraycopy(le64(pieces.length), 0, result, resultPos, 8);
		resultPos += 8;
		for (int i = 0; i < pieces.length; ++i) {
			System.arraycopy(le64(pieces[i].length), 0, result, resultPos, 8);
			resultPos += 8;
			System.arraycopy(pieces[i], 0, result, resultPos, pieces[i].length);
			resultPos += pieces[i].length;
		}
		return result;
	}
}
