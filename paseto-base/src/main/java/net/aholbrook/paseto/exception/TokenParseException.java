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

public class TokenParseException extends PasetoStringException {
	private final Reason reason;
	private int minLength = 0;

	public TokenParseException(Reason reason, String token) {
		super(message(reason, token), token);
		this.reason = reason;
	}

	public Reason getReason() {
		return reason;
	}

	public int getMinLength() {
		return minLength;
	}

	public TokenParseException setMinLength(int minLength) {
		this.minLength = minLength;
		return this;
	}

	public enum Reason {
		MISSING_SECTIONS,
		PAYLOAD_LENGTH
	}

	public static String message(Reason reason, String token) {
		StringBuilder sb = new StringBuilder();

		switch (reason) {
			case MISSING_SECTIONS:
				sb.append("Invalid token: \"")
						.append(token)
						.append("\" unable to locate 3-4 paseto sections.");
				break;

			case PAYLOAD_LENGTH:
				sb.append("Invalid token: \"")
						.append(token)
						.append("\" payload section does not meet minimum length requirements.");
				break;
		}

		return sb.toString();
	}
}
