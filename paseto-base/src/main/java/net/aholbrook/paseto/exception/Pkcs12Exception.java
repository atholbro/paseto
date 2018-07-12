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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class Pkcs12Exception extends RuntimeException {
	private final Reason reason;

	public Pkcs12Exception(FileNotFoundException e) {
		super(e);
		reason = Reason.FILE_NOT_FOUND;
	}

	public Pkcs12Exception(KeyStoreException e) {
		super(e);
		reason = Reason.NO_PKCS12_PROVIDER;
	}

	public Pkcs12Exception(NoSuchAlgorithmException e) {
		super(e);
		reason = Reason.ALGORITHM_NOT_FOUND;
	}

	public Pkcs12Exception(UnrecoverableKeyException e) {
		super(e);
		reason = Reason.UNRECOVERABLE_KEY;
	}

	public Pkcs12Exception(IOException e) {
		super(e);
		if (e.getCause() != null && e.getCause() instanceof UnrecoverableKeyException) {
			reason = Reason.INCORRECT_PASSWORD;
		} else {
			reason = Reason.IO_EXCEPTION;
		}
	}

	public Pkcs12Exception(CertificateException e) {
		super(e);
		reason = Reason.CERTIFICATE_ERROR;
	}

	public Reason getReason() {
		return reason;
	}

	public enum Reason {
		NO_PKCS12_PROVIDER,
		FILE_NOT_FOUND,
		ALGORITHM_NOT_FOUND,
		UNRECOVERABLE_KEY,
		IO_EXCEPTION,
		INCORRECT_PASSWORD,
		CERTIFICATE_ERROR
	}
}
