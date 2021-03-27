package net.aholbrook.paseto.base64.jvm8;

public interface Base64Provider {
	String encodeToString(byte[] bytes);

	byte[] decodeFromString(String s);
}
