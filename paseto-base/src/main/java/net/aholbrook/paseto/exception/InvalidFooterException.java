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

package net.aholbrook.paseto.exception;

import net.aholbrook.paseto.util.StringUtils;

public class InvalidFooterException extends PasetoException {
	private final String given, expected;

	public InvalidFooterException(String given, String expected, String token) {
		super(message(given, expected), token);
		this.given = given;
		this.expected = expected;
	}

	public String getGiven() {
		return given;
	}

	public String getExpected() {
		return expected;
	}

	public static String message(String given, String expected) {
		StringBuilder sb = new StringBuilder();
		sb.append("Invalid footer in token: \"")
				.append(StringUtils.ntes(given))
				.append("\", expected: \"")
				.append(expected)
				.append("\".");
		return sb.toString();
	}
}
