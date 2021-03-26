package net.aholbrook.paseto;

import net.aholbrook.paseto.exception.Pkcs12LoadException;
import net.aholbrook.paseto.util.Pkcs12;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Pkcs12Test {
	private static void assertPkcs12LoadException(Pkcs12LoadException e, Pkcs12LoadException.Reason reason) {
		Assertions.assertEquals(reason, e.getReason(), "reason");
		throw e;
	}

	@Test
	public void pkcs12_load() {
		System.out.println("dir: " + System.getProperty("user.dir"));
		Pkcs12.load("../test-data/p12/rfc_v1_rsa.p12", "testtest", "test");
	}

	@Test
	public void pkcs12_load2() {
		Pkcs12.load("../test-data/p12/test_v1_rsa.p12", "password", "test", "password");
	}

	@Test
	public void pkcs12_loadNotFound() {
		Assertions.assertThrows(Pkcs12LoadException.class, () -> {
			try {
				Pkcs12.load("../test-data/p12/notafile.p12", "testtest", "test", "testtest");
			} catch (Pkcs12LoadException e) {
				assertPkcs12LoadException(e, Pkcs12LoadException.Reason.FILE_NOT_FOUND);
			}
		});
	}

	@Test
	public void pkcs12_loadWrongPassword() {
		Assertions.assertThrows(Pkcs12LoadException.class, () -> {
			try {
				Pkcs12.load("../test-data/p12/rfc_v1_rsa.p12", "wrong", "test", "testtest");
			} catch (Pkcs12LoadException e) {
				assertPkcs12LoadException(e, Pkcs12LoadException.Reason.INCORRECT_PASSWORD);
			}
		});
	}

	@Test
	public void pkcs12_loadWrongAlias() {
		Assertions.assertThrows(Pkcs12LoadException.class, () -> {
			try {
				Pkcs12.load("../test-data/p12/rfc_v1_rsa.p12", "testtest", "wrong", "testtest");
			} catch (Pkcs12LoadException e) {
				assertPkcs12LoadException(e, Pkcs12LoadException.Reason.PRIVATE_KEY_NOT_FOUND);
			}
		});
	}

	@Test
	public void pkcs12_loadWrongKeyPass() {
		Assertions.assertThrows(Pkcs12LoadException.class, () -> {
			try {
				Pkcs12.load("../test-data/p12/rfc_v1_rsa.p12", "testtest", "test", "wrong");
			} catch (Pkcs12LoadException e) {
				assertPkcs12LoadException(e, Pkcs12LoadException.Reason.UNRECOVERABLE_KEY);
			}
		});
	}

	@Test
	public void pkcs12_loadNoCertificate() {
		Assertions.assertThrows(Pkcs12LoadException.class, () -> {
			try {
				Pkcs12.load("../test-data/p12/test_v1_rsa_nopub.p12", "password", "test", "password");
			} catch (Pkcs12LoadException e) {
				assertPkcs12LoadException(e, Pkcs12LoadException.Reason.PUBLIC_KEY_NOT_FOUND);
			}
		});
	}

	@Test
	public void pkcs12_loadCorrupt() {
		Assertions.assertThrows(Pkcs12LoadException.class, () -> {
			try {
				Pkcs12.load("../test-data/p12/test_v1_rsa_corrupt.p12", "password", "test", "password");
			} catch (Pkcs12LoadException e) {
				assertPkcs12LoadException(e, Pkcs12LoadException.Reason.IO_EXCEPTION);
			}
		});
	}

	// Test exception cases which are hard to test via file loading. At least we can verify that the correct reason is
	// set in these cases.
	@Test
	public void pkcs12_exceptions() {
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
	}
}
