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

import net.aholbrook.paseto.crypto.Tuple;
import net.aholbrook.paseto.crypto.exception.CryptoProviderException;
import net.aholbrook.paseto.crypto.v1.V1CryptoProvider;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;

import java.io.IOException;
import java.security.SecureRandom;

public class BouncyCastleV1CryptoProvider extends V1CryptoProvider {
	@Override
	public byte[] randomBytes(int size) {
		byte[] buffer = new byte[size];
		new SecureRandom().nextBytes(buffer);
		return buffer;
	}

	@Override
	public byte[] hkdfExtractAndExpand(byte[] salt, byte[] inputKeyingMaterial, byte[] info) {
		validateHkdfExtractAndExpand(salt, inputKeyingMaterial, info);

		Digest digest = new SHA384Digest();
		HKDFBytesGenerator hkdf = new HKDFBytesGenerator(digest);
		hkdf.init(new HKDFParameters(inputKeyingMaterial, salt, info));

		byte[] out = new byte[HKDF_LEN];
		hkdf.generateBytes(out, 0, out.length);
		return out;
	}

	@Override
	public byte[] hmacSha384(byte[] m, byte[] key) {
		validateHmacSha384(m, key);

		Digest digest = new SHA384Digest();
		HMac hmac = new HMac(digest);

		hmac.init(new KeyParameter(key));
		byte[] out = new byte[hmac.getMacSize()];
		hmac.update(m, 0, m.length);
		hmac.doFinal(out, 0);
		return out;
	}

	private BufferedBlockCipher ase256CtrCipher(boolean forEncryption, byte[] key, byte[] iv) {
		BlockCipher engine = new AESEngine();
		BufferedBlockCipher cipher = new BufferedBlockCipher(new SICBlockCipher(engine));
		CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);

		cipher.init(forEncryption, params);
		return cipher;
	}

	@Override
	public byte[] aes256Ctr(byte[] m, byte[] key, byte[] iv) {
		validateAes256CtrEncrypt(m, key, iv);

		try {
			BufferedBlockCipher cipher = ase256CtrCipher(true, key, iv);

			byte[] cipherText = new byte[cipher.getOutputSize(m.length)];
			int len = cipher.processBytes(m, 0, m.length, cipherText, 0);
			cipher.doFinal(cipherText, len);

			return cipherText;
		} catch (InvalidCipherTextException e) {
			// Not possible since we're not using padding.
			throw new CryptoProviderException("Invalid cipher text in aes256CtrEncrypt.", e);
		}
	}

	@Override
	public byte[] aes256CtrDecrypt(byte[] c, byte[] key, byte[] iv) {
		validateAes256CtrDecrypt(c, key, iv);

		try {
			BufferedBlockCipher cipher = ase256CtrCipher(false, key, iv);

			byte[] clearText = new byte[cipher.getOutputSize(c.length)];
			int len = cipher.processBytes(c, 0, c.length, clearText, 0);
			cipher.doFinal(clearText, len);

			return clearText;
		} catch (InvalidCipherTextException e) {
			// Not possible since we're not using padding.
			throw new CryptoProviderException("Invalid cipher text in aes256CtrDecrypt.", e);
		}
	}

	private PSSSigner pssSha384(boolean forSigning, byte[] key) {
		try {
			byte[] salt = new byte[SHA384_OUT_LEN];
			new SecureRandom().nextBytes(salt);
			// RSA-PSS, SHA-384, MGF1(SHA-384), 48 byte salt length, 0xBC trailer
			PSSSigner pss = new PSSSigner(new RSABlindedEngine(), new SHA384Digest(), new SHA384Digest(),
					SHA384_OUT_LEN, (byte)0xBC);

			if (forSigning) {
				pss.init(true, PrivateKeyFactory.createKey(key));
			} else {
				pss.init(false, PublicKeyFactory.createKey(key));
			}

			return pss;
		} catch (IOException e) {
			throw new CryptoProviderException("IOException", e);
		}
	}

	@Override
	public byte[] rsaSign(byte[] m, byte[] privateKey) {
		validateRsaSign(m, privateKey);

		try {
			PSSSigner pss = pssSha384(true, privateKey);
			pss.update(m, 0, m.length);
			return pss.generateSignature();
		} catch (CryptoException e) {
			// Not documented
			throw new CryptoProviderException("CryptoException", e);
		}
	}

	@Override
	public boolean rsaVerify(byte[] m, byte[] sig, byte[] publicKey) {
		validateRsaVerify(m, sig, publicKey);

		PSSSigner pss = pssSha384(false, publicKey);
		pss.update(m, 0, m.length);
		return pss.verifySignature(sig);
	}

	@Override
	public Tuple<byte[], byte[]> rsaGenerate() {
		RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
		keyGen.init(new RSAKeyGenerationParameters(E, new SecureRandom(), RSA_KEY_SIZE,
				PrimeCertaintyCalculator.getDefaultCertainty(RSA_KEY_SIZE)));
		AsymmetricCipherKeyPair pair = keyGen.generateKeyPair();

		RSAKeyParameters pub = (RSAKeyParameters)pair.getPublic();
		RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)pair.getPrivate();

		// As in BCRSAPrivateKey / BCRSAPublicKey
		AlgorithmIdentifier algo = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
		byte[] publicKey = KeyUtil.getEncodedSubjectPublicKeyInfo(algo, new RSAPublicKey(pub.getModulus(),
				pub.getExponent()));
		byte[] privateKey = KeyUtil.getEncodedPrivateKeyInfo(algo, new RSAPrivateKey(priv.getModulus(),
				priv.getPublicExponent(), priv.getExponent(), priv.getP(), priv.getQ(), priv.getDP(), priv.getDQ(),
				priv.getQInv()));

		return new Tuple<>(privateKey, publicKey);
	}
}
