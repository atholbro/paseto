package net.aholbrook.paseto.encoding;

public interface EncodingProvider {
	String encode(Object o);
	<_Out> _Out decode(String s, Class<_Out> clazz);
}
