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

public class Pkcs12LoadException extends PasetoException {
	private final Reason reason;

	public Pkcs12LoadException(Reason reason) {
		super(message(reason, null));
		this.reason = reason;
	}

	public Pkcs12LoadException(FileNotFoundException e) {
		super(message(Reason.FILE_NOT_FOUND, e), e);
		reason = Reason.FILE_NOT_FOUND;
	}

	public Pkcs12LoadException(KeyStoreException e) {
		super(message(Reason.NO_PKCS12_PROVIDER, e), e);
		reason = Reason.NO_PKCS12_PROVIDER;
	}

	public Pkcs12LoadException(NoSuchAlgorithmException e) {
		super(message(Reason.ALGORITHM_NOT_FOUND, e), e);
		reason = Reason.ALGORITHM_NOT_FOUND;
	}

	public Pkcs12LoadException(UnrecoverableKeyException e) {
		super(message(Reason.UNRECOVERABLE_KEY, e), e);
		reason = Reason.UNRECOVERABLE_KEY;
	}

	public Pkcs12LoadException(IOException e) {
		super(message(e.getCause() != null && e.getCause() instanceof UnrecoverableKeyException
				? Reason.INCORRECT_PASSWORD : Reason.IO_EXCEPTION, e), e);
		if (e.getCause() != null && e.getCause() instanceof UnrecoverableKeyException) {
			reason = Reason.INCORRECT_PASSWORD;
		} else {
			reason = Reason.IO_EXCEPTION;
		}
	}

	public Pkcs12LoadException(CertificateException e) {
		super(message(Reason.CERTIFICATE_ERROR, e), e);
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
		CERTIFICATE_ERROR,
		PRIVATE_KEY_NOT_FOUND,
		PUBLIC_KEY_NOT_FOUND
	}

	private static String message(Reason reason, Throwable e) {
		switch (reason) {
			default: // shouldn't happen unless more "reasons" are added
			case NO_PKCS12_PROVIDER:
				return "Unable to locate provider for PKCS12 files.";
			case FILE_NOT_FOUND:
				return "File not found.";
			case ALGORITHM_NOT_FOUND:
				return "Key algorithm not found - " + e.getLocalizedMessage();
			case UNRECOVERABLE_KEY:
				return "Unrecoverable key - " + e.getLocalizedMessage();
			case IO_EXCEPTION:
				return "IO exception - " + e.getLocalizedMessage();
			case INCORRECT_PASSWORD:
				return "Given keystore and/or key password was incorrect.";
			case CERTIFICATE_ERROR:
				return "Certificate error - " + e.getLocalizedMessage();
			case PRIVATE_KEY_NOT_FOUND:
				return "Unable to locate private key in keystore.";
			case PUBLIC_KEY_NOT_FOUND:
				return "Unable to locate public key / certificate in keystore.";
		}
	}
}
