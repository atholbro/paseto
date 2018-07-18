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

package net.aholbrook.paseto.crypto.v1.bc;

import net.aholbrook.paseto.crypto.base.NonceGenerator;
import net.aholbrook.paseto.crypto.base.Tuple;
import net.aholbrook.paseto.crypto.base.exception.CryptoProviderException;
import net.aholbrook.paseto.crypto.v1.base.HkdfProvider;
import net.aholbrook.paseto.crypto.v1.base.V1CryptoProvider;
import net.aholbrook.paseto.crypto.v1.base.exception.HmacException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class JvmV1CryptoProvider implements V1CryptoProvider {
	private final NonceGenerator nonceGenerator;

	public JvmV1CryptoProvider() {
		this.nonceGenerator = new Jvm8NonceGenerator();
	}

	public JvmV1CryptoProvider(NonceGenerator nonceGenerator) {
		this.nonceGenerator = nonceGenerator;
	}

	@Override
	public byte[] randomBytes(int size) {
		byte[] buffer = new byte[size];
		new SecureRandom().nextBytes(buffer);
		return buffer;
	}

	@Override
	public NonceGenerator getNonceGenerator() {
		return nonceGenerator;
	}

	@Override
	public HkdfProvider getHkdfProvider() {
		return new Hkdf();
	}

	@Override
	public byte[] hmacSha384(byte[] m, byte[] key) {
		try {
			SecretKeySpec sks = new SecretKeySpec(key, "HmacSHA384");
			Mac mac = Mac.getInstance("HmacSHA384");
			mac.init(sks);
			return mac.doFinal(m);
		} catch (NoSuchAlgorithmException e) {
			throw new HmacException("Unable to calculate MAC - HmacSHA384 not found.", e);
		} catch (InvalidKeyException e) {
			throw new HmacException("Unable to calculate MAC - invalid key.", e);
		}
	}

	@Override
	public byte[] aes256Ctr(byte[] m, byte[] key, byte[] iv) {
		try {
			IvParameterSpec ivps = new IvParameterSpec(iv);
			SecretKeySpec sks = new SecretKeySpec(key, "AES");

			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, sks, ivps);

			return cipher.doFinal(m);
		} catch (NoSuchPaddingException e) {
			throw new CryptoProviderException("JVM does not implement NoPadding.", e);
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new CryptoProviderException("JVM does not implement AES CTR.", e);
		} catch (InvalidKeyException e) {
			throw new CryptoProviderException("JVM does not support 256 bit encryption.", e);
		} catch (BadPaddingException e) {
			throw new CryptoProviderException("BadPaddingException", e);
		} catch (IllegalBlockSizeException e) {
			throw new CryptoProviderException("IllegalBlockSizeException", e);
		}
	}

	@Override
	public byte[] aes256CtrDecrypt(byte[] c, byte[] key, byte[] iv) {
		try {
			IvParameterSpec ivps = new IvParameterSpec(iv);
			SecretKeySpec sks = new SecretKeySpec(key, "AES");

			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, sks, ivps);

			return cipher.doFinal(c);
		} catch (NoSuchPaddingException e) {
			throw new CryptoProviderException("JVM does not implement NoPadding.", e);
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new CryptoProviderException("JVM does not implement AES CTR.", e);
		} catch (InvalidKeyException e) {
			throw new CryptoProviderException("JVM does not support 256 bit encryption.", e);
		} catch (BadPaddingException e) {
			throw new CryptoProviderException("BadPaddingException", e);
		} catch (IllegalBlockSizeException e) {
			throw new CryptoProviderException("IllegalBlockSizeException", e);
		}
	}

	@Override
	public byte[] rsaSign(byte[] m, byte[] privateKey) {
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey pk = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey));

			Signature signature = Signature.getInstance("SHA384withRSA/PSS", new BouncyCastleProvider());
			signature.initSign(pk);
			signature.update(m);

			return signature.sign();
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoProviderException("Unable to generate RSA signature - algorithm not found.", e);
		} catch (InvalidKeySpecException e) {
			throw new CryptoProviderException("Unable to generate RSA signature - invalid key spec.", e);
		} catch (InvalidKeyException e) {
			throw new CryptoProviderException("Unable to generate RSA signature - invalid key.", e);
		} catch (SignatureException e) {
			throw new CryptoProviderException("Unable to generate RSA signature - signature error.", e);
		}
	}

	@Override
	public boolean rsaVerify(byte[] m, byte[] sig, byte[] publicKey) {
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(publicKey));

			Signature signature = Signature.getInstance("SHA384withRSA/PSS", new BouncyCastleProvider());
			signature.initVerify(pk);
			signature.update(m);

			return signature.verify(sig);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoProviderException("Unable to generate RSA signature - algorithm not found.", e);
		} catch (InvalidKeySpecException e) {
			throw new CryptoProviderException("Unable to generate RSA signature - invalid key spec.", e);
		} catch (InvalidKeyException e) {
			throw new CryptoProviderException("Unable to generate RSA signature - invalid key.", e);
		} catch (SignatureException e) {
			throw new CryptoProviderException("Unable to generate RSA signature - signature error.", e);
		}
	}

	@Override
	public Tuple<byte[], byte[]> rsaGenerate() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
			KeyPair pair = keyGen.generateKeyPair();

			return new Tuple<>(pair.getPrivate().getEncoded(), pair.getPublic().getEncoded());
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoProviderException("Unable to create RSA Key - No algorithm", e);
		}
	}
}
