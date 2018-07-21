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

package net.aholbrook.paseto.util;

import net.aholbrook.paseto.crypto.Tuple;
import net.aholbrook.paseto.exception.Pkcs12LoadException;

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
	private Pkcs12() {}

	public static Tuple<PrivateKey, PublicKey> load(String keystoreFile, String keystorePass, String alias) {
		return load(keystoreFile, keystorePass, alias, keystorePass);
	}

	public static Tuple<PrivateKey, PublicKey> load(String keystoreFile, String keystorePass, String alias,
			String keyPass) {
		try {
			KeyStore p12 = KeyStore.getInstance("PKCS12");
			p12.load(new FileInputStream(keystoreFile), keystorePass.toCharArray());

			PrivateKey privateKey = (PrivateKey) p12.getKey(alias, keyPass.toCharArray());
			PublicKey publicKey = p12.getCertificate(alias).getPublicKey();

			return new Tuple<>(privateKey, publicKey);
		} catch (FileNotFoundException e) {
			throw new Pkcs12LoadException(e);
		} catch (CertificateException e) {
			throw new Pkcs12LoadException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new Pkcs12LoadException(e);
		} catch (UnrecoverableKeyException e) {
			throw new Pkcs12LoadException(e);
		} catch (IOException e) {
			throw new Pkcs12LoadException(e);
		} catch (KeyStoreException e) {
			throw new Pkcs12LoadException(e);
		}
	}
}
