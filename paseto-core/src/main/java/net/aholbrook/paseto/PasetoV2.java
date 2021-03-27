package net.aholbrook.paseto;

import net.aholbrook.paseto.base64.Base64Provider;
import net.aholbrook.paseto.crypto.KeyPair;
import net.aholbrook.paseto.crypto.NonceGenerator;
import net.aholbrook.paseto.crypto.v2.bc.V2CryptoLoader;
import net.aholbrook.paseto.crypto.v2.bc.V2CryptoProvider;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.exception.DecryptionException;
import net.aholbrook.paseto.exception.PasetoParseException;
import net.aholbrook.paseto.exception.SignatureVerificationException;
import net.aholbrook.paseto.util.PaeUtil;
import net.aholbrook.paseto.util.StringUtils;

public class PasetoV2 extends Paseto {
	private final static String VERSION = "v2";
	public final static String HEADER_LOCAL = VERSION + SEPARATOR + PURPOSE_LOCAL + SEPARATOR; // v2.local.
	public final static String HEADER_PUBLIC = VERSION + SEPARATOR + PURPOSE_PUBLIC + SEPARATOR; // v2.public.

	private final V2CryptoProvider cryptoProvider;

	private PasetoV2(Base64Provider base64Provider, EncodingProvider encodingProvider, V2CryptoProvider cryptoProvider,
			NonceGenerator nonceGenerator) {
		super(base64Provider, encodingProvider, nonceGenerator);
		this.cryptoProvider = cryptoProvider;
	}

	@Override
	public String encrypt(Object payload, byte[] key, String footer) {
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
			return HEADER_LOCAL + base64Provider.encodeToString(nc) + SEPARATOR
					+ base64Provider.encodeToString(footerBytes);
		} else {
			return HEADER_LOCAL + base64Provider.encodeToString(nc);
		}
	}

	@Override
	public <_Payload> _Payload decrypt(String token, byte[] key, String footer, Class<_Payload> payloadClass) {
		// Split token into sections
		String[] sections = split(token);
		if (sections == null) {
			throw new PasetoParseException(PasetoParseException.Reason.MISSING_SECTIONS, token);
		}

		// Check header
		checkHeader(token, sections, HEADER_LOCAL);

		// Decode footer
		String decodedFooter = decodeFooter(token, sections, footer);

		// Decrypt
		byte[] nc = base64Provider.decodeFromString(sections[2]);
		byte[] n = new byte[cryptoProvider.xChaCha20Poly1305IetfNpubbytes()];
		// verify length
		if (nc.length < n.length + 1) {
			throw new PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token)
					.setMinLength(n.length + 1);
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
	public String sign(Object payload, byte[] sk, String footer) {
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
			return HEADER_PUBLIC + base64Provider.encodeToString(msig)
					+ SEPARATOR + base64Provider.encodeToString(footerBytes);
		} else {
			return HEADER_PUBLIC + base64Provider.encodeToString(msig);
		}
	}

	@Override
	public <_Payload> _Payload verify(String token, byte[] pk, String footer, Class<_Payload> payloadClass) {
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
		byte[] msig = base64Provider.decodeFromString(sections[2]);
		byte[] s = new byte[cryptoProvider.ed25519SignBytes()];
		// verify length
		if (msig.length < s.length + 1) {
			throw new PasetoParseException(PasetoParseException.Reason.PAYLOAD_LENGTH, token)
					.setMinLength(s.length + 1);
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
	public KeyPair generateKeyPair() {
		return cryptoProvider.ed25519Generate();
	}

	public static class Builder extends Paseto.Builder {
		V2CryptoProvider v2CryptoProvider;

		public Builder withV2CryptoProvider(V2CryptoProvider v2CryptoProvider) {
			this.v2CryptoProvider = v2CryptoProvider;
			return this;
		}

		@Override
		protected String versionName() {
			return "v2";
		}

		@Override
		protected String cryptoProviderName() {
			return v2CryptoProvider.getClass().getSimpleName();
		}

		@Override
		protected void fillInDefaults() {
			super.fillInDefaults();
			if (v2CryptoProvider == null) { v2CryptoProvider = V2CryptoLoader.getProvider(); }
			if (nonceGenerator == null) { nonceGenerator = v2CryptoProvider.getNonceGenerator(); }
		}

		public PasetoV2 build() {
			fillInDefaults();
			return new PasetoV2(base64Provider, encodingProvider, v2CryptoProvider, nonceGenerator);
		}
	}
}
