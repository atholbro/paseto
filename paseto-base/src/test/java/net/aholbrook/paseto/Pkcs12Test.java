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

package net.aholbrook.paseto;

import net.aholbrook.paseto.util.Pkcs12;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Pkcs12Test {
	@Test
	public void pkcs12_load() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeySpecException {
		System.out.println("dir: " + System.getProperty("user.dir"));

		Tuple<PrivateKey, PublicKey> keys = Pkcs12.load("v1_rsa.p12", "testtest", "test");
		Assert.assertNotNull(keys);
		Assert.assertNotNull(keys.a);
		Assert.assertNotNull(keys.b);

		byte[] privateKey = keys.a.getEncoded();
		byte[] publicKey = keys.b.getEncoded();

		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privateKey2 = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
		PublicKey publicKey2 = kf.generatePublic(new X509EncodedKeySpec(publicKey));

		Assert.assertEquals(keys.a, privateKey2);
		Assert.assertEquals(keys.b, publicKey2);
	}
}
