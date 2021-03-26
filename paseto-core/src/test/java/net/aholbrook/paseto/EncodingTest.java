package net.aholbrook.paseto;

import net.aholbrook.paseto.data.CustomToken;
import net.aholbrook.paseto.data.TokenTestVectors;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.encoding.exception.EncodingException;
import net.aholbrook.paseto.service.Token;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@DisplayName("JSON Serialization / Deserialization")
public class EncodingTest {
	// Basic json encode & decode test.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void token_encodeDecode1(EncodingProvider encodingProvider) {
		String s = encodingProvider.encode(TokenTestVectors.TOKEN_1);
		Token token2 = encodingProvider.decode(s, Token.class);
		Assertions.assertEquals(TokenTestVectors.TOKEN_1, token2, "decoded token");
	}

	// Basic json decode test.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void token_decode1(EncodingProvider encodingProvider) {
		Token token = encodingProvider.decode(TokenTestVectors.TOKEN_1_STRING, Token.class);
		Assertions.assertEquals(TokenTestVectors.TOKEN_1, token, "decoded token");
	}

	// Basic json encode & decode test.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void token_encodeDecode2(EncodingProvider encodingProvider) {
		String s = encodingProvider.encode(TokenTestVectors.TOKEN_2);
		CustomToken token2 = encodingProvider.decode(s, CustomToken.class);
		Assertions.assertEquals(TokenTestVectors.TOKEN_2, token2, "decoded token");
	}

	// Basic json decode test.
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void token_decode2(EncodingProvider encodingProvider) {
		CustomToken token = encodingProvider.decode(TokenTestVectors.TOKEN_2_STRING,
				CustomToken.class);
		Assertions.assertEquals(TokenTestVectors.TOKEN_2, token, "decoded token");
	}

	// encode / decode errors
	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void token_encodeNull(EncodingProvider encodingProvider) {
		String s = encodingProvider.encode(null);
		Assertions.assertNull(s);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void token_decodeNull(EncodingProvider encodingProvider) {
		Token token = encodingProvider.decode(null, Token.class);
		Assertions.assertNull(token);
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void token_decodeEmpty(EncodingProvider encodingProvider) {
		Assertions.assertThrows(EncodingException.class,
				() -> encodingProvider.decode("", Token.class));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void token_decodeError(EncodingProvider encodingProvider) {
		Assertions.assertThrows(EncodingException.class,
				() -> encodingProvider.decode("notjson", Token.class));
	}

	@ParameterizedTest(name = "{displayName} with {0}")
	@MethodSource("net.aholbrook.paseto.Sources#encodingProviders")
	public void token_expiryAsUnixTimestamp(EncodingProvider encodingProvider) {
		Token token = encodingProvider.decode("{\"exp\":0}", Token.class);
		Assertions.assertNotNull(token);
		Assertions.assertNull(token.getExpiration());
	}
}