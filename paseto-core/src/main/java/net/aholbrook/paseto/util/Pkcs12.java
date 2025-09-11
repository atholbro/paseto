package net.aholbrook.paseto.util;

import net.aholbrook.paseto.Version;
import net.aholbrook.paseto.exception.Pkcs12LoadException;
import net.aholbrook.paseto.keys.AsymmetricPublicKey;
import net.aholbrook.paseto.keys.AsymmetricSecretKey;
import net.aholbrook.paseto.keys.KeyPair;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class Pkcs12 {
	private Pkcs12() {
	}

	public static KeyPair load(String keystoreFile, String keystorePass, String alias) {
		return load(keystoreFile, keystorePass, alias, keystorePass);
	}

	public static KeyPair load(String keystoreFile, String keystorePass, String alias, String keyPass) {
		try {
			KeyStore p12 = KeyStore.getInstance("PKCS12");
			p12.load(new FileInputStream(keystoreFile), keystorePass.toCharArray());

			PrivateKey privateKey = (PrivateKey) p12.getKey(alias, keyPass.toCharArray());
			if (privateKey == null) { throw new Pkcs12LoadException(Pkcs12LoadException.Reason.PRIVATE_KEY_NOT_FOUND); }
			Certificate cert = p12.getCertificate(alias);
			if (cert == null) { throw new Pkcs12LoadException(Pkcs12LoadException.Reason.PUBLIC_KEY_NOT_FOUND); }
			PublicKey publicKey = cert.getPublicKey();

			return new KeyPair(
					new AsymmetricSecretKey(privateKey.getEncoded(), Version.V1),
					new AsymmetricPublicKey(publicKey.getEncoded(), Version.V1)
			);
		} catch (FileNotFoundException e) {
			throw new Pkcs12LoadException(e);
		} catch (CertificateException e) {
			throw new Pkcs12LoadException(e); // Unlikely to ever throw.
		} catch (NoSuchAlgorithmException e) {
			throw new Pkcs12LoadException(e); // Unlikely to occur on any modern jvm.
		} catch (UnrecoverableKeyException e) {
			throw new Pkcs12LoadException(e);
		} catch (IOException e) {
			throw new Pkcs12LoadException(e);
		} catch (KeyStoreException e) {
			throw new RuntimeException(e); // This can only occur if you forget to call load, thus this will never throw.
		}
	}
}
