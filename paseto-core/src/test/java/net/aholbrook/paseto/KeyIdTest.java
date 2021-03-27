package net.aholbrook.paseto;

import net.aholbrook.paseto.data.KeyIdTestVectors;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.service.KeyId;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class KeyIdTest {
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void keyId_encodeDecode1(EncodingProvider encodingProvider) {
		String s = encodingProvider.encode(KeyIdTestVectors.KEY_ID_1);
		KeyId keyId = encodingProvider.decode(s, KeyId.class);
		Assertions.assertEquals(KeyIdTestVectors.KEY_ID_1, keyId, "decoded token");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void keyId_encodeDecode2(EncodingProvider encodingProvider) {
		String s = encodingProvider.encode(KeyIdTestVectors.KEY_ID_2);
		KeyId keyId = encodingProvider.decode(s, KeyId.class);
		Assertions.assertEquals(KeyIdTestVectors.KEY_ID_2, keyId, "decoded token");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void keyId_encodeDecodeFooter(EncodingProvider encodingProvider) {
		String s = encodingProvider.encode(KeyIdTestVectors.KEY_ID_FOOTER);
		KeyIdTestVectors.Footer keyId = encodingProvider.decode(s, KeyIdTestVectors.Footer.class);
		Assertions.assertEquals(KeyIdTestVectors.KEY_ID_FOOTER, keyId, "decoded token");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void keyId_decode1(EncodingProvider encodingProvider) {
		KeyId keyId = encodingProvider.decode(KeyIdTestVectors.KEY_ID_1_STRING, KeyId.class);
		Assertions.assertEquals(KeyIdTestVectors.KEY_ID_1, keyId, "decoded token");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void keyId_decode2(EncodingProvider encodingProvider) {
		KeyId keyId = encodingProvider.decode(KeyIdTestVectors.KEY_ID_2_STRING, KeyId.class);
		Assertions.assertEquals(KeyIdTestVectors.KEY_ID_2, keyId, "decoded token");
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void keyId_decodeFooter(EncodingProvider encodingProvider) {
		KeyIdTestVectors.Footer keyId = encodingProvider.decode(KeyIdTestVectors.KEY_ID_FOOTER_STRING,
				KeyIdTestVectors.Footer.class);
		Assertions.assertEquals(KeyIdTestVectors.KEY_ID_FOOTER, keyId, "decoded token");
	}

	@Test
	public void keyId_equals() {
		KeyId kid1 = new KeyId().setKeyId("1");
		KeyId kid2 = new KeyId().setKeyId("1");
		Assertions.assertEquals(kid1, kid1);
		Assertions.assertEquals(kid1, kid2);
		Assertions.assertEquals(kid1.hashCode(), kid2.hashCode());
	}

	@Test
	public void keyId_notEquals() {
		KeyId kid1 = new KeyId().setKeyId("1");
		KeyId kid2 = new KeyId().setKeyId("2");
		Assertions.assertNotEquals(kid1, new Object());
		Assertions.assertFalse(kid1.equals(null));
		Assertions.assertFalse(kid1.equals(1));
		Assertions.assertNotEquals(kid1, kid2);
		Assertions.assertNotEquals(kid1.hashCode(), kid2.hashCode());
	}

	@Test
	public void keyId_toString() {
		KeyId kid = KeyIdTestVectors.KEY_ID_1;
		Assertions.assertEquals(kid.getKeyId(), kid.toString());
	}
}
