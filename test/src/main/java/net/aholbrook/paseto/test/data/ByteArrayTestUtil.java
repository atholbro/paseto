package net.aholbrook.paseto.test.data;

public class ByteArrayTestUtil {
	// since java byte is unsigned
	public static byte[] convertToByteArray(short[] shortArray) {
		byte key[] = new byte[shortArray.length];
		for (int i = 0; i < key.length; ++i) {
			key[i] = (byte) shortArray[i];
		}
		return key;
	}
}
