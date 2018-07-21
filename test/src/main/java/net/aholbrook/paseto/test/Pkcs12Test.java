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

package net.aholbrook.paseto.test;

import net.aholbrook.paseto.exception.Pkcs12LoadException;
import net.aholbrook.paseto.util.Pkcs12;
import org.junit.Assert;
import org.junit.Test;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Pkcs12Test {
	private static void assertPkcs12LoadException(Pkcs12LoadException e, Pkcs12LoadException.Reason reason) {
		Assert.assertEquals("reason", reason, e.getReason());
		throw e;
	}

	@Test
	public void pkcs12_load() {
		System.out.println("dir: " + System.getProperty("user.dir"));
		Pkcs12.load("../test/p12/rfc_v1_rsa.p12", "testtest", "test");
	}

	@Test
	public void pkcs12_load2() {
		Pkcs12.load("../test/p12/test_v1_rsa.p12", "password", "test", "password");
	}

	@Test(expected = Pkcs12LoadException.class)
	public void pkcs12_loadNotFound() {
		try {
			Pkcs12.load("../test/p12/notafile.p12", "testtest", "test", "testtest");
		} catch (Pkcs12LoadException e) {
			assertPkcs12LoadException(e, Pkcs12LoadException.Reason.FILE_NOT_FOUND);
		}
	}

	@Test(expected = Pkcs12LoadException.class)
	public void pkcs12_loadWrongPassword() {
		try {
			Pkcs12.load("../test/p12/rfc_v1_rsa.p12", "wrong", "test", "testtest");
		} catch (Pkcs12LoadException e) {
			assertPkcs12LoadException(e, Pkcs12LoadException.Reason.INCORRECT_PASSWORD);
		}
	}

	@Test(expected = Pkcs12LoadException.class)
	public void pkcs12_loadWrongAlias() {
		try {
			Pkcs12.load("../test/p12/rfc_v1_rsa.p12", "testtest", "wrong", "testtest");
		} catch (Pkcs12LoadException e) {
			assertPkcs12LoadException(e, Pkcs12LoadException.Reason.PRIVATE_KEY_NOT_FOUND);
		}
	}

	@Test(expected = Pkcs12LoadException.class)
	public void pkcs12_loadWrongKeyPass() {
		try {
			Pkcs12.load("../test/p12/rfc_v1_rsa.p12", "testtest", "test", "wrong");
		} catch (Pkcs12LoadException e) {
			assertPkcs12LoadException(e, Pkcs12LoadException.Reason.UNRECOVERABLE_KEY);
		}
	}

	// Test exception cases which are hard to test via file loading. At least we can verify that the correct reason is
	// set in these cases.
	@Test
	public void pkcs12_exceptions() {
		// No provider
		try {
			assertPkcs12LoadException(new Pkcs12LoadException(new KeyStoreException()),
					Pkcs12LoadException.Reason.NO_PKCS12_PROVIDER);
		} catch (Pkcs12LoadException e) {
			// ignore
		}

		// No algorithm
		try {
			assertPkcs12LoadException(new Pkcs12LoadException(new NoSuchAlgorithmException()),
					Pkcs12LoadException.Reason.ALGORITHM_NOT_FOUND);
		} catch (Pkcs12LoadException e) {
			// ignore
		}

		// cert error
		try {
			assertPkcs12LoadException(new Pkcs12LoadException(new CertificateException()),
					Pkcs12LoadException.Reason.CERTIFICATE_ERROR);
		} catch (Pkcs12LoadException e) {
			// ignore
		}

		// io exception
		try {
			assertPkcs12LoadException(new Pkcs12LoadException(new IOException()),
					Pkcs12LoadException.Reason.IO_EXCEPTION);
		} catch (Pkcs12LoadException e) {
			// ignore
		}
	}
}
