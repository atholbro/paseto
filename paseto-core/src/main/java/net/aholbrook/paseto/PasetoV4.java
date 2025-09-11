package net.aholbrook.paseto;

import net.aholbrook.paseto.crypto.NonceGenerator;
import net.aholbrook.paseto.crypto.Pair;
import net.aholbrook.paseto.crypto.v4.V4CryptoLoader;
import net.aholbrook.paseto.crypto.v4.V4CryptoProvider;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.exception.DecryptionException;
import net.aholbrook.paseto.exception.PasetoParseException;
import net.aholbrook.paseto.exception.SignatureVerificationException;
import net.aholbrook.paseto.keys.AsymmetricPublicKey;
import net.aholbrook.paseto.keys.AsymmetricSecretKey;
import net.aholbrook.paseto.keys.KeyPair;
import net.aholbrook.paseto.keys.SymmetricKey;
import net.aholbrook.paseto.util.Base64Utils;
import net.aholbrook.paseto.util.ByteArrayUtils;
import net.aholbrook.paseto.util.PaeUtil;
import net.aholbrook.paseto.util.StringUtils;

import java.util.Arrays;
import java.util.Base64;

public class PasetoV4 extends Paseto {
	private final static String VERSION = "v4";
	public final static String HEADER_LOCAL = VERSION + SEPARATOR + PURPOSE_LOCAL + SEPARATOR; // v4.local.
	public final static String HEADER_PUBLIC = VERSION + SEPARATOR + PURPOSE_PUBLIC + SEPARATOR; // v4.public.

	private final V4CryptoProvider cryptoProvider;

	private PasetoV4(EncodingProvider encodingProvider, V4CryptoProvider cryptoProvider,
			NonceGenerator nonceGenerator) {
		super(encodingProvider, nonceGenerator);
		this.cryptoProvider = cryptoProvider;
	}

	private byte[] concat(byte[] a, byte[] b) {
		byte[] result = new byte[a.length + b.length];
		System.arraycopy(a, 0, result, 0, a.length);
		System.arraycopy(b, 0, result, a.length, b.length);
		return result;
	}

	@Override
	public String encrypt(Object payload, SymmetricKey key, String footer, String implicitAssertion) {
		// Verify key version.
		key.verifyKey(Version.V4);
		if (payload == null) { throw new NullPointerException("payload"); }

		footer = StringUtils.ntes(footer); // convert null to ""
		byte[] payloadBytes = StringUtils.getBytesUtf8(encodingProvider.encode(payload));
		byte[] footerBytes = StringUtils.getBytesUtf8(footer);
		byte[] implicitAssertionBytes = StringUtils.getBytesUtf8(StringUtils.ntes(implicitAssertion));

		byte[] n = nonceGenerator.generateNonce();
		byte[] tmp = new byte[56];
		cryptoProvider.blake2b(tmp, key.getMaterial(), concat(StringUtils.getBytesUtf8("paseto-encryption-key"), n));
		byte[] Ek = Arrays.copyOfRange(tmp, 0, 32);
		byte[] n2 = Arrays.copyOfRange(tmp, 32, 56);
		byte[] Ak = new byte[32];
		cryptoProvider.blake2b(Ak, key.getMaterial(), StringUtils.getBytesUtf8("paseto-auth-key-for-aead"), n);
		byte[] c = new byte[payloadBytes.length];
		cryptoProvider.xChaCha20Xor(c, payloadBytes, n2, Ek);
		byte[] preAuth = PaeUtil.pae(StringUtils.getBytesUtf8(HEADER_LOCAL), n, c, footerBytes, implicitAssertionBytes);
		byte[] t = new byte[32];
		cryptoProvider.blake2b(t, Ak, preAuth);

		byte[] nct = new byte[n.length + c.length + t.length];
		System.arraycopy(n, 0, nct, 0, n.length);
		System.arraycopy(c, 0, nct, n.length, c.length);
		System.arraycopy(t, 0, nct, n.length + c.length, t.length);

		if (footerBytes.length > 0) {
			return HEADER_LOCAL + Base64.getUrlEncoder().withoutPadding().encodeToString(nct) + SEPARATOR
					+ Base64.getUrlEncoder().withoutPadding().encodeToString(footerBytes);
		} else {
			return HEADER_LOCAL + Base64.getUrlEncoder().withoutPadding().encodeToString(nct);
		}
	}

	@Override
	public <_Payload> _Payload decrypt(String token, SymmetricKey key, String footer, Class<_Payload> payloadClass,
			String implicitAssertion) {
		// Verify key version.
		key.verifyKey(Version.V4);

		// Split token into sections
		String[] sections = split(token);
		if (sections == null) {
			throw new PasetoParseException(PasetoParseException.Reason.MISSING_SECTIONS, token);
		}

		// Check header
		checkHeader(token, sections, HEADER_LOCAL);

		// Decode footer
		String decodedFooter = decodeFooter(token, sections, footer);
		byte[] footerBytes = StringUtils.getBytesUtf8(decodedFooter);

		byte[] implicitAssertionBytes = StringUtils.getBytesUtf8(StringUtils.ntes(implicitAssertion));

		// Decrypt
		byte[] nct = Base64Utils.strictBase64UrlDecode(sections[2]);
		if (nct == null) { throw new PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token); }
		byte[] n = Arrays.copyOfRange(nct, 0, 32);
		byte[] t = Arrays.copyOfRange(nct, nct.length - 32, nct.length);
		byte[] c = Arrays.copyOfRange(nct, n.length, nct.length - t.length);

		byte[] tmp = new byte[56];
		cryptoProvider.blake2b(tmp, key.getMaterial(), StringUtils.getBytesUtf8("paseto-encryption-key"), n);
		byte[] Ek = Arrays.copyOfRange(tmp, 0, 32);
		byte[] n2 = Arrays.copyOfRange(tmp, 32, 56);
		byte[] Ak = new byte[32];
		cryptoProvider.blake2b(Ak,  key.getMaterial(), StringUtils.getBytesUtf8("paseto-auth-key-for-aead"), n);
		byte[] preAuth = PaeUtil.pae(StringUtils.getBytesUtf8(HEADER_LOCAL), n, c, footerBytes, implicitAssertionBytes);
		byte[] t2 = new byte[32];
		cryptoProvider.blake2b(t2, Ak, preAuth);
		if (!ByteArrayUtils.isEqual(t, t2)) {
			throw new DecryptionException(token);
		}
		byte[] p = new byte[c.length];
		if (!cryptoProvider.xChaCha20Xor(p, c, n2, Ek)) {
			throw new DecryptionException(token);
		}

		return decode(p, payloadClass);
	}

	@Override
	public String sign(Object payload, AsymmetricSecretKey sk, String footer, String implicitAssertion) {
		// Verify key version.
		sk.verifyKey(Version.V4);

		footer = StringUtils.ntes(footer); // convert null to ""
		byte[] payloadBytes = StringUtils.getBytesUtf8(encodingProvider.encode(payload));
		byte[] footerBytes = StringUtils.getBytesUtf8(footer);

		byte[] m2 = PaeUtil.pae(
				StringUtils.getBytesUtf8(HEADER_PUBLIC),
				payloadBytes,
				footerBytes,
				StringUtils.getBytesUtf8(implicitAssertion != null ? implicitAssertion : "")
		);
		byte[] sig = new byte[cryptoProvider.ed25519SignBytes()];
		cryptoProvider.ed25519Sign(sig, m2, sk.getMaterial());

		byte[] msig = new byte[payloadBytes.length + sig.length];
		System.arraycopy(payloadBytes, 0, msig, 0, payloadBytes.length);
		System.arraycopy(sig, 0, msig, payloadBytes.length, sig.length);

		if (footerBytes.length > 0) {
			return HEADER_PUBLIC + Base64.getUrlEncoder().withoutPadding().encodeToString(msig)
					+ SEPARATOR + Base64.getUrlEncoder().withoutPadding().encodeToString(footerBytes);
		} else {
			return HEADER_PUBLIC + Base64.getUrlEncoder().withoutPadding().encodeToString(msig);
		}
	}

	@Override
	public <_Payload> _Payload verify(String token, AsymmetricPublicKey pk, String footer, Class<_Payload> payloadClass,
			String implicitAssertion) {
		// Verify key version.
		pk.verifyKey(Version.V4);

		// Split token into sections
		String[] sections = split(token);
		if (sections == null) {
			throw new PasetoParseException(PasetoParseException.Reason.MISSING_SECTIONS, token);
		}

		// Check header
		checkHeader(token, sections, HEADER_PUBLIC);

		// Decode footer
		String decodedFooter = decodeFooter(token, sections, footer);

		// Verify
		byte[] msig = Base64.getUrlDecoder().decode(sections[2]);
		byte[] s = new byte[cryptoProvider.ed25519SignBytes()];
		// verify length
		if (msig.length < s.length + 1) {
			throw new PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token)
					.setMinLength(s.length + 1);
		}
		byte[] m = new byte[msig.length - s.length];
		System.arraycopy(msig, msig.length - s.length, s, 0, s.length);
		System.arraycopy(msig, 0, m, 0, m.length);

		byte[] m2 = PaeUtil.pae(
				StringUtils.getBytesUtf8(HEADER_PUBLIC),
				m,
				StringUtils.getBytesUtf8(decodedFooter),
				StringUtils.getBytesUtf8(implicitAssertion != null ? implicitAssertion : "")
		);
		if (!cryptoProvider.ed25519Verify(s, m2, pk.getMaterial())) {
			throw new SignatureVerificationException(token);
		}

		// Convert from JSON
		return decode(m, payloadClass);
	}

	@Override
	public KeyPair generateKeyPair() {
		Pair<byte[], byte[]> rawKey = cryptoProvider.ed25519Generate();
		return new KeyPair(
				new AsymmetricSecretKey(rawKey.a, Version.V4),
				new AsymmetricPublicKey(rawKey.b, Version.V4)
		);
	}

	public static class Builder extends Paseto.Builder {
		V4CryptoProvider v4CryptoProvider;

		public Builder withV4CryptoProvider(V4CryptoProvider v4CryptoProvider) {
			this.v4CryptoProvider = v4CryptoProvider;
			return this;
		}

		@Override
		protected void fillInDefaults() {
			super.fillInDefaults();
			if (v4CryptoProvider == null) { v4CryptoProvider = V4CryptoLoader.getProvider(); }
			if (nonceGenerator == null) { nonceGenerator = v4CryptoProvider.getNonceGenerator(); }
		}

		public PasetoV4 build() {
			fillInDefaults();
			return new PasetoV4(encodingProvider, v4CryptoProvider, nonceGenerator);
		}
	}
}
