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

package net.aholbrook.paseto.crypto.v1;

import net.aholbrook.paseto.crypto.NonceGenerator;
import net.aholbrook.paseto.crypto.Tuple;

public interface V1CryptoProvider {
	// RNG
	byte[] randomBytes(int size);

	// Nonce
	NonceGenerator getNonceGenerator();

	// HKDF
	HkdfProvider getHkdfProvider();

	// Hmac SHA 384
	byte[] hmacSha384(byte[] m, byte[] key);

	// AES-256-CTR
	byte[] aes256Ctr(byte[] m, byte[] key, byte[] iv);
	byte[] aes256CtrDecrypt(byte[] c, byte[] key, byte[] iv);

	// RSA Signatures
	byte[] rsaSign(byte[] m, byte[] privateKey);
	boolean rsaVerify(byte[] m, byte[] sig, byte[] publicKey);
	Tuple<byte[], byte[]> rsaGenerate();

}
