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

import net.aholbrook.paseto.base64.base.Base64Provider;
import net.aholbrook.paseto.crypto.base.NonceGenerator;
import net.aholbrook.paseto.crypto.v1.base.V1CryptoProvider;
import net.aholbrook.paseto.crypto.v2.base.V2CryptoProvider;
import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.exception.InvalidFooterException;
import net.aholbrook.paseto.exception.InvalidHeaderException;
import net.aholbrook.paseto.util.StringUtils;

import java.nio.charset.Charset;
import java.util.regex.Pattern;

public abstract class Paseto<_Payload> {
	final static String SEPARATOR = ".";
	final static String PURPOSE_LOCAL = "local";
	final static String PURPOSE_PUBLIC = "public";

	final EncodingProvider encodingProvider;
	final NonceGenerator nonceGenerator;
	final Base64Provider base64Provider;

	Paseto(EncodingProvider encodingProvider, NonceGenerator nonceGenerator, Base64Provider base64Provider) {
		this.encodingProvider = encodingProvider;
		this.nonceGenerator = nonceGenerator;
		this.base64Provider = base64Provider;
	}

	public abstract String encrypt(_Payload payload, byte[] key, String footer);
	public abstract _Payload decrypt(String token, byte[] key, String footer, Class<_Payload> payloadClass);
	public abstract String sign(_Payload payload, byte[] key, String footer);
	public abstract _Payload verify(String token, byte[] pk, String footer, Class<_Payload> payloadClass);

	public String encrypt(_Payload payload, byte[] key) {
		return encrypt(payload, key, null);
	}

	public String encrypt(_Payload payload, byte[] key, Object footer) {
		return encrypt(payload, key, encodingProvider.toJson(footer));
	}

	public _Payload decrypt(String token, byte[] key, Class<_Payload> payloadClass) {
		return decrypt(token, key, null, payloadClass);
	}

	public _Payload decrypt(String token, byte[] key, Object footer, Class<_Payload> payloadClass) {
		return decrypt(token, key, encodingProvider.toJson(footer), payloadClass);
	}

	public String sign(_Payload payload, byte[] sk) {
		return sign(payload, sk, null);
	}

	public String sign(_Payload payload, byte[] sk, Object footer) {
		return sign(payload, sk, encodingProvider.toJson(footer));
	}

	public _Payload verify(String token, byte[] pk, Class<_Payload> payloadClass) {
		return verify(token, pk, null, payloadClass);
	}

	public _Payload verify(String token, byte[] pk, Object footer, Class<_Payload> payloadClass) {
		return verify(token, pk, encodingProvider.toJson(footer), payloadClass);
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
		_Payload payload = decrypt(token, pk, payloadClass);
		_Footer footer = extractFooter(token, footerClass);
		return new Tuple<>(payload, footer);
	}

	public String extractFooter(String token) {
		return split(token)[3];
	}

	public <_Footer> _Footer extractFooter(String token, Class<_Footer> footerClass) {
		String footer = extractFooter(token);
		if (!StringUtils.isEmpty(footer)) {
			return encodingProvider.fromJson(extractFooter(token), footerClass);
		} else {
			return null;
		}
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
		String decodedFooter = "";

		// Check footer if given, must match.
		boolean footerRequired = !StringUtils.isEmpty(expectedFooter);
		// both must either be present or not present
		if (!StringUtils.isEmpty(sections[3]) == footerRequired) {
			// only decode if the footer is required
			if (footerRequired) {
				String userFooter = StringUtils.ntes(sections[3]);
				decodedFooter = new String(base64Provider.decodeFromString(userFooter), Charset.forName("UTF-8"));

				// StringUtils.isEqual compares all bytes
				if (!StringUtils.isEqual(decodedFooter, expectedFooter)) {
					throw new InvalidFooterException(decodedFooter, expectedFooter, token);
				}
			}
		} else {
			throw new InvalidFooterException(StringUtils.ntes(sections[3]), StringUtils.ntes(expectedFooter), token);
		}

		return decodedFooter;
	}

	_Payload decode(byte[] payload, Class<_Payload> payloadClass) {
		return encodingProvider.fromJson(new String(payload, Charset.forName("UTF-8")), payloadClass);
	}

	public static class Builder<_Payload> {
		protected int version = 2;
		protected EncodingProvider encodingProvider;
		protected V1CryptoProvider v1CryptoProvider;
		protected V2CryptoProvider v2CryptoProvider;
		protected Base64Provider base64Provider;
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

		public Builder<_Payload> withBase64(Base64Provider base64Provider) {
			this.base64Provider = base64Provider;
			return this;
		}

		public Builder<_Payload> withTestingNonceGenerator(NonceGenerator nonceGenerator) {
			this.nonceGenerator = nonceGenerator;
			return this;
		}

		public Paseto<_Payload> build() {
			if (encodingProvider == null) { throw new NullPointerException("json implementation required."); }
			if (base64Provider == null) { throw new NullPointerException("base64 implementation required."); }

			switch (version) {
				case 1:
					if (v1CryptoProvider == null) { throw new NullPointerException("crypto implementation required."); }
					if (nonceGenerator == null) { nonceGenerator = v1CryptoProvider.getNonceGenerator(); }

					return new PasetoV1<>(encodingProvider, v1CryptoProvider, nonceGenerator, base64Provider);
				case 2:
					if (v2CryptoProvider == null) { throw new NullPointerException("crypto implementation required."); }
					if (nonceGenerator == null) { nonceGenerator = v2CryptoProvider.getNonceGenerator(); }

					return new PasetoV2<>(encodingProvider, v2CryptoProvider, nonceGenerator, base64Provider);
				default:
					return null;
			}

		}
	}
}
