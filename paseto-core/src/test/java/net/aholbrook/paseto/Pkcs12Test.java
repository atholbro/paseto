package net.aholbrook.paseto;

import net.aholbrook.paseto.exception.Pkcs12LoadException;
import net.aholbrook.paseto.util.Pkcs12;
import org.junit.jupiter.api.*;
import org.mockito.ArgumentMatchers;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
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

	private void pkcs12_mock_load(Throwable ex, Runnable test) {
		try {
			try (MockedStatic<KeyStore> keyStoreStatic = Mockito.mockStatic(KeyStore.class)) {
				KeyStore keyStore = Mockito.mock(KeyStore.class);

				Mockito.doThrow(ex)
						.when(keyStore)
						.load(ArgumentMatchers.any(), ArgumentMatchers.nullable(char[].class));
				keyStoreStatic.when(() -> KeyStore.getInstance("PKCS12"))
						.thenReturn(keyStore);

				Assertions.assertNotNull(keyStore, "Failed to mock KeyStore.load().");
				test.run();
			}
		} catch (Throwable e) {
			Assertions.fail("Failed to mock KeyStore.load().", e);
		}
	}

	private void pkcs12_mock_getKey(Throwable ex, Runnable test) {
		try {
			try (MockedStatic<KeyStore> keyStoreStatic = Mockito.mockStatic(KeyStore.class)) {
				KeyStore keyStore = Mockito.mock(KeyStore.class);
				Mockito.doThrow(ex)
						.when(keyStore)
						.getKey(ArgumentMatchers.any(), ArgumentMatchers.any());
				keyStoreStatic.when(() -> KeyStore.getInstance("PKCS12"))
						.thenReturn(keyStore);

				Assertions.assertNotNull(keyStore, "Failed to mock KeyStore.getKey().");
				test.run();
			}
		} catch (Throwable e) {
			Assertions.fail("Failed to mock KeyStore.getKey().", e);
		}
	}

	@Test
	@Order(value = Integer.MAX_VALUE)
	public void pkcs12_loadCertificateException() {
		pkcs12_mock_load(new CertificateException("mocked"), () -> {
			Throwable e = Assertions.assertThrows(Pkcs12LoadException.class,
					() -> Pkcs12.load("../test-data/p12/rfc_v1_rsa.p12", "testtest", "test"));
			Assertions.assertEquals("Certificate error - mocked", e.getMessage());
		});
	}

	@Test
	@Order(value = Integer.MAX_VALUE)
	public void pkcs12_loadNoSuchAlgorithmException() {
		pkcs12_mock_load(new NoSuchAlgorithmException("mocked"), () -> {
			Throwable e = Assertions.assertThrows(Pkcs12LoadException.class,
					() -> Pkcs12.load("../test-data/p12/rfc_v1_rsa.p12", "testtest", "test"));
			Assertions.assertEquals("Key algorithm not found - mocked", e.getMessage());
		});
	}

	@Test
	@Order(value = Integer.MAX_VALUE)
	public void pkcs12_loadKeyStoreException() {
		pkcs12_mock_getKey(new KeyStoreException("mocked"), () -> {
			Throwable e = Assertions.assertThrows(RuntimeException.class,
					() -> Pkcs12.load("../test-data/p12/rfc_v1_rsa.p12", "testtest", "test"));
			Assertions.assertEquals("java.security.KeyStoreException: mocked", e.getMessage());
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
