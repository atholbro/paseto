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
import net.aholbrook.paseto.crypto.v1.V1CryptoProvider;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.exception.SignatureVerificationException;
import net.aholbrook.paseto.exception.TokenParseException;
import net.aholbrook.paseto.util.Base64;
import net.aholbrook.paseto.util.ByteArrayUtils;
import net.aholbrook.paseto.util.PaeUtil;
import net.aholbrook.paseto.util.StringUtils;

public class PasetoV1<_Payload> extends Paseto<_Payload> {
	private final static String VERSION = "v1";
	public final static String HEADER_LOCAL = VERSION + SEPARATOR + PURPOSE_LOCAL + SEPARATOR; // v1.local.
	public final static String HEADER_PUBLIC = VERSION + SEPARATOR + PURPOSE_PUBLIC + SEPARATOR; // v1.public.

	private final static byte[] HKDF_INFO_EK = StringUtils.getBytesUtf8("paseto-encryption-key");
	private final static byte[] HKDF_INFO_AK = StringUtils.getBytesUtf8("paseto-auth-key-for-aead");

	private final V1CryptoProvider cryptoProvider;

	PasetoV1(EncodingProvider encodingProvider, V1CryptoProvider cryptoProvider, NonceGenerator nonceGenerator) {
		super(encodingProvider, nonceGenerator);
		this.cryptoProvider = cryptoProvider;
	}

	@Override
	public String encrypt(_Payload payload, byte[] key, String footer) {
		footer = StringUtils.ntes(footer); // convert null to ""
		byte[] payloadBytes = StringUtils.getBytesUtf8(encodingProvider.encode(payload));
		byte[] footerBytes = StringUtils.getBytesUtf8(footer);

		// Generate n
		byte[] random = nonceGenerator.generateNonce();
		byte[] n = new byte[V1CryptoProvider.NONCE_SIZE];
		System.arraycopy(cryptoProvider.hmacSha384(payloadBytes, random), 0, n, 0, n.length);

		// Split N into salt/nonce
		byte[] salt = new byte[V1CryptoProvider.HKDF_SALT_LEN];
		byte[] nonce = new byte[V1CryptoProvider.HKDF_SALT_LEN];
		System.arraycopy(n, 0, salt, 0, salt.length);
		System.arraycopy(n, salt.length, nonce, 0, nonce.length);

		// Create ek/ak for AEAD
		byte[] ek = cryptoProvider.hkdfExtractAndExpand(salt, key, HKDF_INFO_EK);
		byte[] ak = cryptoProvider.hkdfExtractAndExpand(salt, key, HKDF_INFO_AK);

		byte[] c = cryptoProvider.aes256CtrEncrypt(payloadBytes, ek, nonce);
		byte[] preAuth = PaeUtil.pae(StringUtils.getBytesUtf8(HEADER_LOCAL), n, c, footerBytes);
		byte[] t = cryptoProvider.hmacSha384(preAuth, ak);

		byte[] nct = new byte[n.length + c.length + t.length];
		System.arraycopy(n, 0, nct, 0, n.length);
		System.arraycopy(c, 0, nct, n.length, c.length);
		System.arraycopy(t, 0, nct, n.length + c.length, t.length);

		if (footerBytes.length > 0) {
			return HEADER_LOCAL + Base64.encodeToString(nct) + SEPARATOR
					+ Base64.encodeToString(footerBytes);
		} else {
			return HEADER_LOCAL + Base64.encodeToString(nct);
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
		byte[] nct = Base64.decodeFromString(sections[2]);
		byte[] n = new byte[V1CryptoProvider.NONCE_SIZE];
		byte[] t = new byte[V1CryptoProvider.SHA384_OUT_LEN];
		// verify length
		if (nct.length < n.length + t.length + 1) {
			throw new TokenParseException(TokenParseException.Reason.PAYLOAD_LENGTH, token)
					.setMinLength(n.length + t.length + 1);
		}
		byte[] c = new byte[nct.length - n.length - t.length];
		System.arraycopy(nct, 0, n, 0, n.length);
		System.arraycopy(nct, n.length, c, 0, c.length);
		System.arraycopy(nct, n.length + c.length, t, 0, t.length);

		// Split N into salt/nonce
		byte[] salt = new byte[V1CryptoProvider.HKDF_SALT_LEN];
		byte[] nonce = new byte[V1CryptoProvider.HKDF_SALT_LEN];
		System.arraycopy(n, 0, salt, 0, salt.length);
		System.arraycopy(n, salt.length, nonce, 0, nonce.length);

		// Create ek/ak for AEAD
		byte[] ek = cryptoProvider.hkdfExtractAndExpand(salt, key, HKDF_INFO_EK);
		byte[] ak = cryptoProvider.hkdfExtractAndExpand(salt, key, HKDF_INFO_AK);

		byte[] preAuth = PaeUtil.pae(StringUtils.getBytesUtf8(HEADER_LOCAL), n, c,
				StringUtils.getBytesUtf8(decodedFooter));
		byte[] t2 = cryptoProvider.hmacSha384(preAuth, ak);
		if (!ByteArrayUtils.isEqual(t, t2)) {
			throw new SignatureVerificationException(token);
		}

		byte[] m = cryptoProvider.aes256CtrDecrypt(c, ek, nonce);

		// Convert from JSON
		return decode(m, payloadClass);
	}

	@Override
	public String sign(_Payload payload, byte[] pk, String footer) {
		footer = StringUtils.ntes(footer); // convert null to ""
		byte[] payloadBytes = StringUtils.getBytesUtf8(encodingProvider.encode(payload));
		byte[] footerBytes = StringUtils.getBytesUtf8(footer);

		byte[] m2 = PaeUtil.pae(StringUtils.getBytesUtf8(HEADER_PUBLIC), payloadBytes, footerBytes);
		byte[] sig = cryptoProvider.rsaSign(m2, pk);

		byte[] msig = new byte[sig.length + payloadBytes.length];
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
		byte[] s = new byte[V1CryptoProvider.RSA_SIGNATURE_LEN];
		// verify length
		if (msig.length < s.length + 1) {
			throw new TokenParseException(TokenParseException.Reason.PAYLOAD_LENGTH, token)
					.setMinLength(s.length + 1);
		}
		byte[] m = new byte[msig.length - s.length];
		System.arraycopy(msig, msig.length - s.length, s, 0, s.length);
		System.arraycopy(msig, 0, m, 0, m.length);

		byte[] m2 = PaeUtil.pae(StringUtils.getBytesUtf8(HEADER_PUBLIC), m, StringUtils.getBytesUtf8(decodedFooter));
		if (!cryptoProvider.rsaVerify(m2, s, pk)) {
			throw new SignatureVerificationException(token);
		}

		// Convert from JSON
		return decode(m, payloadClass);
	}

	@Override
	public Tuple<byte[], byte[]> generateKeyPair() {
		return cryptoProvider.rsaGenerate();
	}
}
