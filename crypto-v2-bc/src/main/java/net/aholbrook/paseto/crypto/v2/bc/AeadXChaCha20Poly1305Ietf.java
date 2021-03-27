package net.aholbrook.paseto.crypto.v2.bc;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

// See https://www.scottbrady91.com/C-Sharp/XChaCha20-Poly1305-dotnet
// and https://github.com/daviddesmet/NaCl.Core
public class AeadXChaCha20Poly1305Ietf {
	private static final int[] SIGMA = new int[] { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 };

	private AeadXChaCha20Poly1305Ietf() {}

	public static boolean encrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) {
		return chaCha20Poly1305(true, out, in, ad, nonce, key);
	}

	public static boolean decrypt(byte[] out, byte[] in, byte[] ad, byte[] nonce, byte[] key) {
		return chaCha20Poly1305(false, out, in, ad, nonce, key);
	}

	private static boolean chaCha20Poly1305(boolean encrypt, byte[] out, byte[] in, byte[] ad, byte[] nonce,
			byte[] key) {
		try {
			ChaCha20Poly1305 chacha = new ChaCha20Poly1305();
			byte[] iv = new byte[12];
			System.arraycopy(nonce, 16, iv, 4, 8);
			byte[] subkey = createSubkey(nonce, key);
			CipherParameters params = new ParametersWithIV(new KeyParameter(subkey), iv);
			chacha.init(encrypt, params);
			chacha.processAADBytes(ad, 0, ad.length);
			int len = chacha.processBytes(in, 0, in.length, out, 0);
			chacha.doFinal(out, len);
			return true;
		} catch (Throwable e) {
			return false;
		}
	}

	private static int[] createState(byte[] nonce, byte[] key) {
		int[] state = new int[16];

		state[0] = SIGMA[0];
		state[1] = SIGMA[1];
		state[2] = SIGMA[2];
		state[3] = SIGMA[3];
		Pack.littleEndianToInt(key, 0, state, 4, 8);
		Pack.littleEndianToInt(nonce, 0, state, 12, 4);

		return state;
	}

	public static byte[] createSubkey(byte[] nonce, byte[] key) {
		int[] state = createState(nonce, key);
		shuffleState(state);
		byte[] subkey = new byte[32];
		Pack.intToLittleEndian(state, 0, 4, subkey, 0);
		Pack.intToLittleEndian(state, 12, 4, subkey, 16);
		return subkey;
	}

	private static void shuffleState(int[] state) {
		for (int idx = 0; idx < 10; ++idx) {
			quarterRound(state, 0, 4, 8, 12);
			quarterRound(state, 1, 5, 9, 13);
			quarterRound(state, 2, 6, 10, 14);
			quarterRound(state, 3, 7, 11, 15);
			quarterRound(state, 0, 5, 10, 15);
			quarterRound(state, 1, 6, 11, 12);
			quarterRound(state, 2, 7, 8, 13);
			quarterRound(state, 3, 4, 9, 14);
		}
	}

	private static void quarterRound(int[] s, int a, int b, int c, int d) {
		s[a] += s[b];
		s[d] ^= s[a];
		s[d] = s[d] << 16 | s[d] >>> 16;

		s[c] += s[d];
		s[b] ^= s[c];
		s[b] = s[b] << 12 | s[b] >>> 20;

		s[a] += s[b];
		s[d] ^= s[a];
		s[d] = s[d] << 8 | s[d] >>> 24;

		s[c] += s[d];
		s[b] ^= s[c];
		s[b] = s[b] << 7 | s[b] >>> 25;
	}
}
