package net.aholbrook.paseto;

import net.aholbrook.paseto.crypto.TestNonceGenerator;
import net.aholbrook.paseto.data.TestVector;
import net.aholbrook.paseto.util.StringUtils;
import org.junit.jupiter.api.Assertions;

import java.nio.charset.StandardCharsets;

public abstract class PasetoTest {
	protected <_TokenType, _Footer> void encryptTestVector(Paseto.Builder builder, TestVector<_TokenType, _Footer> tv) {
		Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
		Assertions.assertNotNull(paseto, "paseto V1 instance");

		String token;
		if (tv.getFooter() != null) {
			token = paseto.encrypt(tv.getPayload(), tv.getLocalKey(), tv.getFooter());
		} else {
			token = paseto.encrypt(tv.getPayload(), tv.getLocalKey());
		}

		Assertions.assertEquals(tv.getToken(), token, "Generated token does not match test vector.");
	}

	protected <_TokenType, _Footer> void decryptTestVector(Paseto.Builder builder, TestVector<_TokenType, _Footer> tv) {
		Paseto paseto = builder.withNonceGenerator(new TestNonceGenerator(tv.getNonce())).build();
		Assertions.assertNotNull(paseto, "paseto V1 instance");

		_TokenType payload;
		if (tv.getFooter() != null) {
			payload = paseto.decrypt(tv.getToken(), tv.getLocalKey(), tv.getFooter(),
					tv.getPayloadClass());
		} else {
			payload = paseto.decrypt(tv.getToken(), tv.getLocalKey(), tv.getPayloadClass());
		}

		Assertions.assertEquals(tv.getPayload(), payload, "Decrypted payload does not match test vector.");
	}

	protected <_TokenType, _Footer> void signTestVector(Paseto.Builder builder, TestVector<_TokenType, _Footer> tv,
			boolean assertSigned) {
		Paseto paseto = builder.build();
		Assertions.assertNotNull(paseto, "paseto V1 instance");

		String token;
		if (tv.getFooter() != null) {
			token = paseto.sign(tv.getPayload(), tv.getSecretKey(),
					tv.getFooter());
		} else {
			token = paseto.sign(tv.getPayload(), tv.getSecretKey());
		}

		if (assertSigned) {
			Assertions.assertEquals(tv.getToken(), token, "Generated token does not match test vector.");
		}

		// Now verify the signature (we can't use the token in the test vector as the signature will change each time.
		_TokenType decoded;
		if (tv.getFooter() != null) {
			decoded = paseto.verify(token, tv.getPublicKey(), tv.getFooter(), tv.getPayloadClass());
		} else {
			decoded = paseto.verify(token, tv.getPublicKey(), tv.getPayloadClass());
		}

		Assertions.assertEquals(tv.getPayload(), decoded, "Decoded payload does not match test vector.");
	}

	protected <_TokenType, _Footer> void verifyTestVector(Paseto.Builder builder, TestVector<_TokenType, _Footer> tv) {
		Paseto paseto = builder.build();
		Assertions.assertNotNull(paseto, "paseto V1 instance");

		_TokenType payload;
		if (tv.getFooter() != null) {
			payload = paseto.verify(tv.getToken(), tv.getPublicKey(), tv.getFooter(), tv.getPayloadClass());
		} else {
			payload = paseto.verify(tv.getToken(), tv.getPublicKey(), tv.getPayloadClass());
		}

		Assertions.assertEquals(tv.getPayload(), payload, "Verified payload does not match test vector.");
	}

	protected String modify(String token, int[] indices) {
		byte[] tokenBytes = StringUtils.getBytesUtf8(token);
		for (int i : indices) {
			tokenBytes[i] ^= 1;
		}
		return new String(tokenBytes, StandardCharsets.UTF_8);
	}
}
