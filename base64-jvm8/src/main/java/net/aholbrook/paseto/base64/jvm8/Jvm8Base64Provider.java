package net.aholbrook.paseto.base64.jvm8;

import net.aholbrook.paseto.base64.Base64Provider;

public class Jvm8Base64Provider implements Base64Provider {
	@Override
	public String encodeToString(byte[] bytes) {
		return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	@Override
	public byte[] decodeFromString(String s) {
		return java.util.Base64.getUrlDecoder().decode(s);
	}
}
