package net.aholbrook.paseto.util;

public class PaeUtil {
	private PaeUtil() {
	}

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
