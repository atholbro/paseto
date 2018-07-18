package net.aholbrook.paseto.meta;

import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.encoding.json.jackson.JacksonJsonProvider;
import net.aholbrook.paseto.test.ClaimVerificationTestBase;

public class ClaimVerificationTest extends ClaimVerificationTestBase {
	@Override
	protected EncodingProvider getEncodingProvider() {
		return new JacksonJsonProvider();
	}
}
