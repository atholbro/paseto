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

public class ByteArrayRangeException extends CryptoProviderException {
	private final String arg;
	private final int minBound;
	private final int maxBound;

	public ByteArrayRangeException(String arg, int minBound, int maxBound) {
		this(arg, minBound, maxBound, null);
	}

	public ByteArrayRangeException(String arg, int minBound, int maxBound, Throwable throwable) {
		super(message(arg, minBound, maxBound), throwable);
		this.arg = arg;
		this.minBound = minBound;
		this.maxBound = maxBound;
	}

	public String getArg() {
		return arg;
	}

	public int getMinBound() {
		return minBound;
	}

	public int getMaxBound() {
		return maxBound;
	}

	private static String message(String arg, int minBound, int maxBound) {
		StringBuilder sb = new StringBuilder();
		sb.append(arg)
				.append(": length outside of range ")
				.append(minBound).append("..").append(maxBound)
				.append(".");
		return sb.toString();
	}
}
