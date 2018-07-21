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

public class ByteArrayUtils {
	private ByteArrayUtils() {}

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
