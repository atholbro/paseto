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
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;
import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.exception.InvalidFooterException;
import net.aholbrook.paseto.exception.InvalidHeaderException;
import net.aholbrook.paseto.util.Base64;
import net.aholbrook.paseto.util.StringUtils;

import java.nio.charset.Charset;
import java.util.regex.Pattern;

public abstract class Paseto<_Payload> {
	final static String SEPARATOR = ".";
	final static String PURPOSE_LOCAL = "local";
	final static String PURPOSE_PUBLIC = "public";

	final EncodingProvider encodingProvider;
	final NonceGenerator nonceGenerator;

	Paseto(EncodingProvider encodingProvider, NonceGenerator nonceGenerator) {
		this.encodingProvider = encodingProvider;
		this.nonceGenerator = nonceGenerator;
	}

	public abstract String encrypt(_Payload payload, byte[] key, String footer);
	public abstract _Payload decrypt(String token, byte[] key, String footer, Class<_Payload> payloadClass);
	public abstract String sign(_Payload payload, byte[] key, String footer);
	public abstract _Payload verify(String token, byte[] pk, String footer, Class<_Payload> payloadClass);
	public abstract Tuple<byte[], byte[]> generateKeyPair();

	public String encrypt(_Payload payload, byte[] key) {
		return encrypt(payload, key, null);
	}

	public String encrypt(_Payload payload, byte[] key, Object footer) {
		return encrypt(payload, key, encodingProvider.encode(footer));
	}

	public _Payload decrypt(String token, byte[] key, Class<_Payload> payloadClass) {
		return decrypt(token, key, null, payloadClass);
	}

	public _Payload decrypt(String token, byte[] key, Object footer, Class<_Payload> payloadClass) {
		return decrypt(token, key, encodingProvider.encode(footer), payloadClass);
	}

	public String sign(_Payload payload, byte[] sk) {
		return sign(payload, sk, null);
	}

	public String sign(_Payload payload, byte[] sk, Object footer) {
		return sign(payload, sk, encodingProvider.encode(footer));
	}

	public _Payload verify(String token, byte[] pk, Class<_Payload> payloadClass) {
		return verify(token, pk, null, payloadClass);
	}

	public _Payload verify(String token, byte[] pk, Object footer, Class<_Payload> payloadClass) {
		return verify(token, pk, encodingProvider.encode(footer), payloadClass);
	}

	public Tuple<_Payload, String> decryptWithFooter(String token, byte[] key, Class<_Payload> payloadClass) {
		_Payload payload = decrypt(token, key, payloadClass);
		String footer = extractFooter(token);
		return new Tuple<>(payload, footer);
	}

	public <_Footer> Tuple<_Payload, _Footer> decryptWithFooter(String token, byte[] key, Class<_Payload> payloadClass,
			Class<_Footer> footerClass) {
		_Payload payload = decrypt(token, key, payloadClass);
		_Footer footer = extractFooter(token, footerClass);
		return new Tuple<>(payload, footer);
	}

	public Tuple<_Payload, String> verifyWithFooter(String token, byte[] pk, Class<_Payload> payloadClass) {
		_Payload payload = verify(token, pk, payloadClass);
		String footer = extractFooter(token);
		return new Tuple<>(payload, footer);
	}

	public <_Footer> Tuple<_Payload, _Footer> verifyWithFooter(String token, byte[] pk, Class<_Payload> payloadClass,
			Class<_Footer> footerClass) {
		_Payload payload = verify(token, pk, payloadClass);
		_Footer footer = extractFooter(token, footerClass);
		return new Tuple<>(payload, footer);
	}

	public String extractFooter(String token) {
		String footer = split(token)[3];
		if (!StringUtils.isEmpty(footer)) {
			return StringUtils.fromUtf8Bytes(Base64.decodeFromString(footer));
		}

		return null;
	}

	public <_Footer> _Footer extractFooter(String token, Class<_Footer> footerClass) {
		String footer = extractFooter(token);
		if (!StringUtils.isEmpty(footer)) {
			return encodingProvider.decode(footer, footerClass);
		}

		return null;
	}

	/**
	 * Splits a Paseto token into its 4 sections: VERSION, PURPOSE, PAYLOAD, FOOTER.
	 *
	 * If the token does not contain a footer, then the 4th string in the array will be null. If the string does
	 * not contain either 3 or 4 sections separated by a period (ASCII 2E) then a null array will be returned as the
	 * token cannot be valid.
	 *
	 * @param token Paseto token.
	 * @return Array of 4 strings, each containing 1 paseto token section. null if string cannot be a Paseto token.
	 */
	String[] split(String token) {
		if (!StringUtils.isEmpty(token)) {
			String[] tokens = token.split(Pattern.quote(SEPARATOR));

			if (tokens.length == 4) {
				return tokens;
			} else if (tokens.length == 3) {
				return new String[] { tokens[0], tokens[1], tokens[2], null };
			}
		}

		return null;
	}

	void checkHeader(String token, String[] sections, String expectedHeader) {
		if (!token.startsWith(expectedHeader)) {
			throw new InvalidHeaderException(sections[0] + SEPARATOR + sections[1], expectedHeader, token);
		}
	}

	String decodeFooter(String token, String[] sections, String expectedFooter) {
		String userFooter = StringUtils.ntes(sections[3]);
		String decodedFooter = new String(Base64.decodeFromString(userFooter), Charset.forName("UTF-8"));

		// Check the footer if expected footer is not empty, otherwise we just return the footer without checking. This
		// is find though, as the footer is covered by the token PAE signature. This check exists for proper error
		// reporting, and is not a requirement for security.
		if (!StringUtils.isEmpty(expectedFooter) && !StringUtils.isEqual(decodedFooter, expectedFooter)) {
			throw new InvalidFooterException(decodedFooter, expectedFooter, token);
		}

		return decodedFooter;
	}

	_Payload decode(byte[] payload, Class<_Payload> payloadClass) {
		return encodingProvider.decode(new String(payload, Charset.forName("UTF-8")), payloadClass);
	}

	public static class Builder<_Payload> {
		protected int version = 2;
		protected EncodingProvider encodingProvider;
		protected V1CryptoProvider v1CryptoProvider;
		protected V2CryptoProvider v2CryptoProvider;
		protected NonceGenerator nonceGenerator;

		public Builder<_Payload> v1(V1CryptoProvider v1CryptoProvider) {
			this.v1CryptoProvider = v1CryptoProvider;
			this.version = 1;
			return this;
		}

		public Builder<_Payload> v2(V2CryptoProvider v2CryptoProvider) {
			this.v2CryptoProvider = v2CryptoProvider;
			this.version = 2;
			return this;
		}

		public Builder<_Payload> withJson(EncodingProvider encodingProvider) {
			this.encodingProvider = encodingProvider;
			return this;
		}

		public Builder<_Payload> withTestingNonceGenerator(NonceGenerator nonceGenerator) {
			this.nonceGenerator = nonceGenerator;
			return this;
		}

		public Paseto<_Payload> build() {
			if (encodingProvider == null) { throw new NullPointerException("json implementation required."); }

			switch (version) {
				case 1:
					if (v1CryptoProvider == null) { throw new NullPointerException("crypto implementation required."); }
					if (nonceGenerator == null) { nonceGenerator = v1CryptoProvider.getNonceGenerator(); }

					return new PasetoV1<>(encodingProvider, v1CryptoProvider, nonceGenerator);
				case 2:
					if (v2CryptoProvider == null) { throw new NullPointerException("crypto implementation required."); }
					if (nonceGenerator == null) { nonceGenerator = v2CryptoProvider.getNonceGenerator(); }

					return new PasetoV2<>(encodingProvider, v2CryptoProvider, nonceGenerator);
				default:
					return null;
			}

		}
	}
}
