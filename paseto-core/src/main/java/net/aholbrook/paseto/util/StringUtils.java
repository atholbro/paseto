package net.aholbrook.paseto.util;

import java.nio.charset.Charset;

public class StringUtils {
	private StringUtils() {}

	/**
	 * Returns a safe string by converting a null string reference into an empty string.
	 * @param s String reference, which may be null.
	 * @return s or "" if s == null
	 */
	public static String ntes(String s) {
		if (s == null) { return ""; }
		return s;
	}

	/**
	 * Safely determine if a string is empty.
	 *
	 * This function considers a string to be empty if its null or "".
	 *
	 * @param s String to check.
	 * @return true if the string is null or "", false otherwise.
	 */
	public static boolean isEmpty(String s) {
		// Note trim is not performed on purpose as we want exact matching.
		return ntes(s).length() == 0;
	}

	/**
	 * Encodes this String into a sequence of bytes using the UTF-8 charset, storing the result into a new byte array.
	 * @param s string to encode
	 * @return The resultant byte array.
	 */
	public static byte[] getBytesUtf8(String s) {
		return ntes(s).getBytes(Charset.forName("UTF-8"));
	}

	/**
	 * Decodes a string from a sequence of bytes using the UTF-8 charset.
	 *
	 * This is the inverse of getBytesUtf8().
	 * @param bytes Array of UTF-8 bytes.
	 * @return String
	 */
	public static String fromUtf8Bytes(byte[] bytes) {
		if (bytes == null || bytes.length == 0) { return ""; }
		return new String(bytes, Charset.forName("UTF-8"));
	}

	/**
	 * Compares all bytes in the given strings for equivalence ensuring that all bytes are checked for constant timing.
	 *
	 * If the two given strings are of different length, then the user string is compared with itself before
	 * returning false. Therefore, input from the user should be passed into the first argument.
	 *
	 * See: http://codahale.com/a-lesson-in-timing-attacks
	 *
	 * @param user Input from the user.
	 * @param expected The expected byte array.
	 * @return true if user.equals(expected), false otherwise.
	 */
	public static boolean isEqual(String user, String expected) {
		return ByteArrayUtils.isEqual(getBytesUtf8(user), getBytesUtf8(expected));
	}
}
