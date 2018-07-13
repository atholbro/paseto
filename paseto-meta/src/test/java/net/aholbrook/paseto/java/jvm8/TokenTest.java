package net.aholbrook.paseto.java.jvm8;

import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.encoding.json.jackson.JacksonJsonProvider;
import net.aholbrook.paseto.test.TokenTestBase;

public class TokenTest extends TokenTestBase {
	@Override
	protected EncodingProvider getEncodingProvider() {
		return new JacksonJsonProvider();
	}
}
