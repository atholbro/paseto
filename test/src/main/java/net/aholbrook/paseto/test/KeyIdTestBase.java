package net.aholbrook.paseto.test;

import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.test.data.KeyIdTestVectors;
import org.junit.Assert;
import org.junit.Test;

public abstract class KeyIdTestBase {
	protected abstract EncodingProvider getEncodingProvider();

	@Test
	public void keyId_encodeDecode1() {
		EncodingProvider encodingProvider = getEncodingProvider();
		String s = encodingProvider.toJson(KeyIdTestVectors.KEY_ID_1);
		KeyId keyId = encodingProvider.fromJson(s, KeyId.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_1, keyId);
	}

	@Test
	public void keyId_encodeDecode2() {
		EncodingProvider encodingProvider = getEncodingProvider();
		String s = encodingProvider.toJson(KeyIdTestVectors.KEY_ID_2);
		KeyId keyId = encodingProvider.fromJson(s, KeyId.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_2, keyId);
	}

	@Test
	public void keyId_encodeDecodeFooter() {
		EncodingProvider encodingProvider = getEncodingProvider();
		String s = encodingProvider.toJson(KeyIdTestVectors.KEY_ID_FOOTER);
		KeyIdTestVectors.Footer keyId = encodingProvider.fromJson(s, KeyIdTestVectors.Footer.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_FOOTER, keyId);
	}

	@Test
	public void keyId_decode1() {
		EncodingProvider encodingProvider = getEncodingProvider();
		KeyId keyId = encodingProvider.fromJson(KeyIdTestVectors.KEY_ID_1_STRING, KeyId.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_1, keyId);
	}

	@Test
	public void keyId_decode2() {
		EncodingProvider encodingProvider = getEncodingProvider();
		KeyId keyId = encodingProvider.fromJson(KeyIdTestVectors.KEY_ID_2_STRING, KeyId.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_2, keyId);
	}

	@Test
	public void keyId_decodeFooter() {
		EncodingProvider encodingProvider = getEncodingProvider();
		KeyIdTestVectors.Footer keyId = encodingProvider.fromJson(KeyIdTestVectors.KEY_ID_FOOTER_STRING,
				KeyIdTestVectors.Footer.class);
		Assert.assertEquals("decoded token", KeyIdTestVectors.KEY_ID_FOOTER, keyId);
	}
}
