package net.aholbrook.paseto.util;

public class ByteArrayUtils {
	private ByteArrayUtils() {
	}

	/**
	 * Compare two byte arrays without failing fast.
	 *
	 * If the two given byte arrays are of different length, then the user array is compared with itself before
	 * returning false. Therefore, input from the user should be passed into the first argument.
	 *
	 * See: http://codahale.com/a-lesson-in-timing-attacks
	 *
	 * @param user Input from the user.
	 * @param expected The expected byte array.
	 * @return true if the arrays are equal, false if not.
	 */
	public static boolean isEqual(byte[] user, byte[] expected) {
		if (user.length != expected.length) {
			isEqual(user, user); // compare against self to not leak length
			return false;
		}

		int result = 0;
		for (int i = 0; i < user.length; ++i) {
			result |= user[i] ^ expected[i];
		}
		return result == 0;
	}
}
