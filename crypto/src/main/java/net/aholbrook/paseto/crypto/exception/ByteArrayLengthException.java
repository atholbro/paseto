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

package net.aholbrook.paseto.crypto.exception;

public class ByteArrayLengthException extends CryptoProviderException {
	private final String arg;
	private final int len;
	private final int required;
	private final boolean exact;

	public ByteArrayLengthException(String arg, int len, int required) {
		this(arg, len, required, true, null);
	}

	public ByteArrayLengthException(String arg, int len, int required, boolean exact) {
		this(arg, len, required, exact, null);
	}

	public ByteArrayLengthException(String arg, int len, int required, boolean exact, Throwable cause) {
		super(message(arg, len, required, exact), cause);
		this.arg = arg;
		this.len = len;
		this.required = required;
		this.exact = exact;
	}

	public String getArg() {
		return arg;
	}

	public int getLen() {
		return len;
	}

	public int getRequired() {
		return required;
	}

	public boolean isExact() {
		return exact;
	}

	private static String message(String arg, int len, int required, boolean min) {
		StringBuilder sb = new StringBuilder();
		sb.append(arg)
				.append(": ")
				.append(required)
				.append(exact ? " exact " : " ")
				.append("bytes required, given ")
				.append(len)
				.append(" bytes .");
		return sb.toString();
	}
}
