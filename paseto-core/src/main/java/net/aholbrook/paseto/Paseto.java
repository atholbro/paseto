package net.aholbrook.paseto;

import net.aholbrook.paseto.base64.Base64Provider;
import net.aholbrook.paseto.crypto.KeyPair;
import net.aholbrook.paseto.crypto.NonceGenerator;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.exception.InvalidFooterException;
import net.aholbrook.paseto.exception.InvalidHeaderException;
import net.aholbrook.paseto.util.StringUtils;

import java.nio.charset.Charset;
import java.util.regex.Pattern;

public abstract class Paseto {
	final static String SEPARATOR = ".";
	final static String PURPOSE_LOCAL = "local";
	final static String PURPOSE_PUBLIC = "public";

	final Base64Provider base64Provider;
	final EncodingProvider encodingProvider;
	final NonceGenerator nonceGenerator;

	public Paseto(Base64Provider base64Provider, EncodingProvider encodingProvider, NonceGenerator nonceGenerator) {
		this.base64Provider = base64Provider;
		this.encodingProvider = encodingProvider;
		this.nonceGenerator = nonceGenerator;
	}

	public abstract String encrypt(Object payload, byte[] key, String footer);

	public abstract <_Payload> _Payload decrypt(String token, byte[] key, String footer, Class<_Payload> payloadClass);

	public abstract String sign(Object payload, byte[] key, String footer);

	public abstract <_Payload> _Payload verify(String token, byte[] pk, String footer, Class<_Payload> payloadClass);

	public abstract KeyPair generateKeyPair();

	public String encrypt(Object payload, byte[] key) {
		return encrypt(payload, key, null);
	}

	public String encrypt(Object payload, byte[] key, Object footer) {
		return encrypt(payload, key, encodingProvider.encode(footer));
	}

	public <_Payload> _Payload decrypt(String token, byte[] key, Class<_Payload> payloadClass) {
		return decrypt(token, key, null, payloadClass);
	}

	public <_Payload> _Payload decrypt(String token, byte[] key, Object footer, Class<_Payload> payloadClass) {
		return decrypt(token, key, encodingProvider.encode(footer), payloadClass);
	}

	public String sign(Object payload, byte[] sk) {
		return sign(payload, sk, null);
	}

	public String sign(Object payload, byte[] sk, Object footer) {
		return sign(payload, sk, encodingProvider.encode(footer));
	}

	public <_Payload> _Payload verify(String token, byte[] pk, Class<_Payload> payloadClass) {
		return verify(token, pk, null, payloadClass);
	}

	public <_Payload> _Payload verify(String token, byte[] pk, Object footer, Class<_Payload> payloadClass) {
		return verify(token, pk, encodingProvider.encode(footer), payloadClass);
	}

	public <_Payload> TokenWithFooter<_Payload, String> decryptWithFooter(String token, byte[] key,
			Class<_Payload> payloadClass) {
		_Payload payload = decrypt(token, key, payloadClass);
		String footer = extractFooter(token);
		return new TokenWithFooter<>(payload, footer);
	}

	public <_Payload, _Footer> TokenWithFooter<_Payload, _Footer> decryptWithFooter(String token, byte[] key,
			Class<_Payload> payloadClass, Class<_Footer> footerClass) {
		_Payload payload = decrypt(token, key, payloadClass);
		_Footer footer = extractFooter(token, footerClass);
		return new TokenWithFooter<>(payload, footer);
	}

	public <_Payload> TokenWithFooter<_Payload, String> verifyWithFooter(String token, byte[] pk,
			Class<_Payload> payloadClass) {
		_Payload payload = verify(token, pk, payloadClass);
		String footer = extractFooter(token);
		return new TokenWithFooter<>(payload, footer);
	}

	public <_Payload, _Footer> TokenWithFooter<_Payload, _Footer> verifyWithFooter(String token, byte[] pk,
			Class<_Payload> payloadClass, Class<_Footer> footerClass) {
		_Payload payload = verify(token, pk, payloadClass);
		_Footer footer = extractFooter(token, footerClass);
		return new TokenWithFooter<>(payload, footer);
	}

	public String extractFooter(String token) {
		String footer = split(token)[3];
		if (!StringUtils.isEmpty(footer)) {
			return StringUtils.fromUtf8Bytes(base64Provider.decodeFromString(footer));
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
				return new String[] {tokens[0], tokens[1], tokens[2], null};
			}
		}

		return null;
	}

	void checkHeader(String token, String[] sections, String expectedHeader) {
		if (!token.startsWith(expectedHeader)) {
			throw new InvalidHeaderException(sections[0] + SEPARATOR + sections[1] + SEPARATOR, expectedHeader, token);
		}
	}

	String decodeFooter(String token, String[] sections, String expectedFooter) {
		String userFooter = StringUtils.ntes(sections[3]);
		String decodedFooter = new String(base64Provider.decodeFromString(userFooter), Charset.forName("UTF-8"));

		// Check the footer if expected footer is not empty, otherwise we just return the footer without checking. This
		// is find though, as the footer is covered by the token PAE signature. This check exists for proper error
		// reporting, and is not a requirement for security.
		if (!StringUtils.isEmpty(expectedFooter) && !StringUtils.isEqual(decodedFooter, expectedFooter)) {
			throw new InvalidFooterException(decodedFooter, expectedFooter, token);
		}

		return decodedFooter;
	}

	<_Payload> _Payload decode(byte[] payload, Class<_Payload> payloadClass) {
		return encodingProvider.decode(new String(payload, Charset.forName("UTF-8")), payloadClass);
	}
}
