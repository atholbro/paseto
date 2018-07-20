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

import net.aholbrook.paseto.crypto.NonceGenerator;
import net.aholbrook.paseto.crypto.Tuple;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.exception.DecryptionException;
import net.aholbrook.paseto.exception.SignatureVerificationException;
import net.aholbrook.paseto.exception.TokenParseException;
import net.aholbrook.paseto.util.Base64;
import net.aholbrook.paseto.util.PaeUtil;
import net.aholbrook.paseto.util.StringUtils;

public class PasetoV2<_Payload> extends Paseto<_Payload> {
	private final static String VERSION = "v2";
	private final static String HEADER_LOCAL = VERSION + SEPARATOR + PURPOSE_LOCAL + SEPARATOR; // v2.local.
	private final static String HEADER_PUBLIC = VERSION + SEPARATOR + PURPOSE_PUBLIC + SEPARATOR; // v2.public.

	private final V2CryptoProvider cryptoProvider;
	
	PasetoV2(EncodingProvider encodingProvider, V2CryptoProvider cryptoProvider, NonceGenerator nonceGenerator) {
		super(encodingProvider,  nonceGenerator);
		this.cryptoProvider = cryptoProvider;
	}

	@Override
	public String encrypt(_Payload payload, byte[] key, String footer) {
		footer = StringUtils.ntes(footer); // convert null to ""
		byte[] payloadBytes = StringUtils.getBytesUtf8(encodingProvider.encode(payload));
		byte[] footerBytes = StringUtils.getBytesUtf8(footer);

		byte nonce[] = nonceGenerator.generateNonce();
		byte[] n = new byte[cryptoProvider.xChaCha20Poly1305IetfNpubbytes()];
		cryptoProvider.blake2b(n, payloadBytes, nonce);

		byte[] preAuth = PaeUtil.pae(StringUtils.getBytesUtf8(HEADER_LOCAL), n, footerBytes);

		byte[] c = new byte[payloadBytes.length + cryptoProvider.xChaCha20Poly1305IetfAbytes()];
		cryptoProvider.aeadXChaCha20Poly1305IetfEncrypt(c, payloadBytes, preAuth, n, key);

		byte[] nc = new byte[n.length + c.length];
		System.arraycopy(n, 0, nc, 0, n.length);
		System.arraycopy(c, 0, nc, n.length, c.length);

		if (footerBytes.length > 0) {
			return HEADER_LOCAL + Base64.encodeToString(nc) + SEPARATOR
					+ Base64.encodeToString(footerBytes);
		} else {
			return HEADER_LOCAL + Base64.encodeToString(nc);
		}
	}

	@Override
	public _Payload decrypt(String token, byte[] key, String footer, Class<_Payload> payloadClass) {
		// Split token into sections
		String[] sections = split(token);
		if (sections == null) {
			throw new TokenParseException(TokenParseException.Reason.MISSING_SECTIONS, token);
		}

		// Check header
		checkHeader(token, sections, HEADER_LOCAL);

		// Decode footer
		String decodedFooter = decodeFooter(token, sections, footer);

		// Decrypt
		byte[] nc = Base64.decodeFromString(sections[2]);
		byte[] n = new byte[cryptoProvider.xChaCha20Poly1305IetfNpubbytes()];
		// verify length
		if (nc.length < n.length + 1) {
			throw new TokenParseException(TokenParseException.Reason.PAYLOAD_LENGTH, token);
		}
		byte[] c = new byte[nc.length - n.length];
		System.arraycopy(nc, 0, n, 0, n.length);
		System.arraycopy(nc, n.length, c, 0, c.length);

		byte[] preAuth = PaeUtil.pae(StringUtils.getBytesUtf8(HEADER_LOCAL), n, StringUtils.getBytesUtf8(decodedFooter));
		byte[] p = new byte[c.length - cryptoProvider.xChaCha20Poly1305IetfAbytes()];
		if (!cryptoProvider.aeadXChaCha20Poly1305IetfDecrypt(p, c, preAuth, n, key)) {
			throw new DecryptionException(token);
		}

		// Convert from JSON
		return decode(p, payloadClass);
	}

	@Override
	public String sign(_Payload payload, byte[] sk, String footer) {
		footer = StringUtils.ntes(footer); // convert null to ""
		byte[] payloadBytes = StringUtils.getBytesUtf8(encodingProvider.encode(payload));
		byte[] footerBytes = StringUtils.getBytesUtf8(footer);

		byte[] m2 = PaeUtil.pae(StringUtils.getBytesUtf8(HEADER_PUBLIC), payloadBytes, footerBytes);
		byte[] sig = new byte[cryptoProvider.ed25519SignBytes()];
		cryptoProvider.ed25519Sign(sig, m2, sk);

		byte[] msig = new byte[payloadBytes.length + sig.length];
		System.arraycopy(payloadBytes, 0, msig, 0, payloadBytes.length);
		System.arraycopy(sig, 0, msig, payloadBytes.length, sig.length);

		if (footerBytes.length > 0) {
			return HEADER_PUBLIC + Base64.encodeToString(msig)
					+ SEPARATOR + Base64.encodeToString(footerBytes);
		} else {
			return HEADER_PUBLIC + Base64.encodeToString(msig);
		}
	}

	@Override
	public _Payload verify(String token, byte[] pk, String footer, Class<_Payload> payloadClass) {
		// Split token into sections
		String[] sections = split(token);
		if (sections == null) {
			throw new TokenParseException(TokenParseException.Reason.MISSING_SECTIONS, token);
		}

		// Check header
		checkHeader(token, sections, HEADER_PUBLIC);

		// Decode footer
		String decodedFooter = decodeFooter(token, sections, footer);

		// Verify
		byte[] msig = Base64.decodeFromString(sections[2]);
		byte[] s = new byte[cryptoProvider.ed25519SignBytes()];
		// verify length
		if (msig.length < s.length + 1) {
			throw new TokenParseException(TokenParseException.Reason.PAYLOAD_LENGTH, token);
		}
		byte[] m = new byte[msig.length - s.length];
		System.arraycopy(msig, msig.length - s.length, s, 0, s.length);
		System.arraycopy(msig, 0, m, 0, m.length);

		byte[] m2 = PaeUtil.pae(StringUtils.getBytesUtf8(HEADER_PUBLIC), m, StringUtils.getBytesUtf8(decodedFooter));
		if (!cryptoProvider.ed25519Verify(s, m2, pk)) {
			throw new SignatureVerificationException(token);
		}

		// Convert from JSON
		return decode(m, payloadClass);
	}

	@Override
	public Tuple<byte[], byte[]> generateKeyPair() {
		return cryptoProvider.ed25519Generate();
	}
}
