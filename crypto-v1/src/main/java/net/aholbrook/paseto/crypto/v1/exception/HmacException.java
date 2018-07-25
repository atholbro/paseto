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

package net.aholbrook.paseto.crypto.v1.exception;

import net.aholbrook.paseto.crypto.exception.CryptoProviderException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HmacException extends CryptoProviderException {
	private Reason reason;

	public HmacException(NoSuchAlgorithmException cause) {
		super(message(Reason.INTERNAL_LIBRARY_ERROR), cause);
		this.reason = Reason.INTERNAL_LIBRARY_ERROR;
	}

	public HmacException(InvalidKeyException cause) {
		super(message(Reason.INTERNAL_LIBRARY_ERROR), cause);
		this.reason = Reason.INTERNAL_LIBRARY_ERROR;
	}

	public HmacException(IllegalArgumentException cause) {
		super(message(Reason.EMPTY_KEY), cause);
		this.reason = Reason.EMPTY_KEY;
	}

	public Reason getReason() {
		return reason;
	}

	public enum Reason {
		EMPTY_KEY,
		INTERNAL_LIBRARY_ERROR
	}

	private static String message(Reason reason) {
		switch (reason) {
			case EMPTY_KEY:
				return "Empty or null key.";
			default:
			case INTERNAL_LIBRARY_ERROR:
				return "Unexpected exception occurred.";
		}
	}
}
