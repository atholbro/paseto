package net.aholbrook.paseto.meta;

import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.encoding.json.jackson.JacksonJsonProvider;
import net.aholbrook.paseto.test.EncodingTestBase;

public class EncodingTest extends EncodingTestBase {
	@Override
	protected EncodingProvider getEncodingProvider() {
		return new JacksonJsonProvider();
	}
}
