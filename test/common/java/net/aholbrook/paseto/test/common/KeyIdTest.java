package net.aholbrook.paseto.test.common;

import net.aholbrook.paseto.encoding.EncodingLoader;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.test.common.data.KeyIdTestVectors;
import org.junit.Assert;
import org.junit.Test;

public class KeyIdTest {
	private EncodingProvider encodingProvider() {
		return EncodingLoader.getProvider();
	}

	@Test
	public void keyId_encodeDecode1() {
		EncodingProvider encodingProvider = encodingProvider();
		String s = encodingProvider.encode(KeyIdTestVectors.KEY_ID_1);
		KeyId keyId = encodingProvider.decode(s, KeyId.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_1, keyId);
	}

	@Test
	public void keyId_encodeDecode2() {
		EncodingProvider encodingProvider = encodingProvider();
		String s = encodingProvider.encode(KeyIdTestVectors.KEY_ID_2);
		KeyId keyId = encodingProvider.decode(s, KeyId.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_2, keyId);
	}

	@Test
	public void keyId_encodeDecodeFooter() {
		EncodingProvider encodingProvider = encodingProvider();
		String s = encodingProvider.encode(KeyIdTestVectors.KEY_ID_FOOTER);
		KeyIdTestVectors.Footer keyId = encodingProvider.decode(s, KeyIdTestVectors.Footer.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_FOOTER, keyId);
	}

	@Test
	public void keyId_decode1() {
		EncodingProvider encodingProvider = encodingProvider();
		KeyId keyId = encodingProvider.decode(KeyIdTestVectors.KEY_ID_1_STRING, KeyId.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_1, keyId);
	}

	@Test
	public void keyId_decode2() {
		EncodingProvider encodingProvider = encodingProvider();
		KeyId keyId = encodingProvider.decode(KeyIdTestVectors.KEY_ID_2_STRING, KeyId.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_2, keyId);
	}

	@Test
	public void keyId_decodeFooter() {
		EncodingProvider encodingProvider = encodingProvider();
		KeyIdTestVectors.Footer keyId = encodingProvider.decode(KeyIdTestVectors.KEY_ID_FOOTER_STRING,
				KeyIdTestVectors.Footer.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_FOOTER, keyId);
	}

	@Test
	public void keyId_equals() {
		KeyId kid1 = new KeyId().setKeyId("1");
		KeyId kid2 = new KeyId().setKeyId("1");
		Assert.assertEquals(kid1, kid1);
		Assert.assertEquals(kid1, kid2);
		Assert.assertEquals(kid1.hashCode(), kid2.hashCode());
	}

	@Test
	public void keyId_notEquals() {
		KeyId kid1 = new KeyId().setKeyId("1");
		KeyId kid2 = new KeyId().setKeyId("2");
		Assert.assertNotEquals(kid1, new Object());
		Assert.assertEquals(false, kid1.equals(null));
		Assert.assertEquals(false, kid1.equals(1));
		Assert.assertNotEquals(kid1, kid2);
		Assert.assertNotEquals(kid1.hashCode(), kid2.hashCode());
	}
}
