package net.aholbrook.paseto.util;

public class Base64 {
	private Base64() {}

	public static String encodeToString(byte[] bytes) {
		return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	public static byte[] decodeFromString(String s) {
		return java.util.Base64.getUrlDecoder().decode(s);
	}
}
