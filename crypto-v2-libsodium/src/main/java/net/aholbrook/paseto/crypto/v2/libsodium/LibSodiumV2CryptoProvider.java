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

package net.aholbrook.paseto.crypto.v2.libsodium;

import com.goterl.lazycode.lazysodium.LazySodiumJava;
import com.goterl.lazycode.lazysodium.SodiumJava;
import net.aholbrook.paseto.crypto.Tuple;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;

public class LibSodiumV2CryptoProvider extends V2CryptoProvider {
	private final LazySodiumJava sodium;

	public LibSodiumV2CryptoProvider() {
		this(new LazySodiumJava(new SodiumJava()));
	}

	public LibSodiumV2CryptoProvider(LazySodiumJava sodium) {
		this.sodium = sodium;
	}

	@Override
	public boolean blake2b(byte[] out, byte[] in, byte[] key) {
		validateBlake2b(out, in, key);
		return sodium.cryptoGenericHash(out, out.length, in, in.length, key, key.length);
	}

	@Override
	public byte[] randomBytes(int size) {
		return sodium.randomBytesBuf(size);
	}

	@Override
	public boolean aeadXChaCha20Poly1305IetfEncrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) {
		validateAeadXChaCha20Poly1305IetfEncrypt(out, in, ad, nonce, key);

		long[] outLen = new long[] { out.length };
		return sodium.cryptoAeadXChaCha20Poly1305IetfEncrypt(out, outLen, in, in.length, ad, ad.length, null,
				nonce, key);
	}

	@Override
	public boolean aeadXChaCha20Poly1305IetfDecrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) {
		validateAeadXChaCha20Poly1305IetfDecrypt(out, in, ad, nonce, key);

		long[] outLen = new long[] { out.length };
		return sodium.cryptoAeadXChaCha20Poly1305IetfDecrypt(out, outLen, null, in, in.length, ad, ad.length,
				nonce, key);
	}

	@Override
	public boolean ed25519Sign(byte[] sig, byte[] m, byte[] sk) {
		validateEd25519Sign(sig, m, sk);

		long[] sigLen = new long[] { sig.length };
		return sodium.cryptoSignDetached(sig, sigLen, m, m.length, sk);
	}

	@Override
	public boolean ed25519Verify(byte[] sig, byte[] m, byte[] pk) {
		validateEd25519Verify(sig, m, pk);
		return sodium.cryptoSignVerifyDetached(sig, m, m.length, pk);
	}

	@Override
	public byte[] ed25519SkToPk(byte[] sk) {
		validateEd25519PublicKey(sk);
		byte[] pk = new byte[ed25519SignPublicKeyBytes()];


		sodium.cryptoSignEd25519SkToPk(pk, sk);
		return pk;
	}

	@Override
	public Tuple<byte[], byte[]> ed25519Generate() {
		byte[] sk = new byte[ed25519SignSecretKeyBytes()];
		byte[] pk = new byte[ed25519SignPublicKeyBytes()];
		sodium.cryptoSignKeypair(pk, sk);
		return new Tuple<>(sk, pk);
	}
}
