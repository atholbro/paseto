package net.aholbrook.paseto;

import net.aholbrook.paseto.crypto.v1.V1CryptoProvider;
import net.aholbrook.paseto.crypto.v1.bc.BouncyCastleV1CryptoProvider;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;
import net.aholbrook.paseto.crypto.v2.bc.BouncyCastleV2CryptoProvider;
import net.aholbrook.paseto.crypto.v4.V4CryptoProvider;
import net.aholbrook.paseto.crypto.v4.bc.BouncyCastleV4CryptoProvider;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.encoding.json.gson.GsonJsonProvider;
import net.aholbrook.paseto.encoding.json.jackson.JacksonJsonProvider;

import java.util.stream.Stream;

public class Sources {
	private Sources() {
	}

	static Stream<EncodingProvider> encodingProviders() {
		return Stream.of(
				new JacksonJsonProvider() {
					@Override
					public String toString() {
						return "jackson";
					}
				},
				new GsonJsonProvider() {
					@Override
					public String toString() {
						return "gson";
					}
				});
	}

	static Stream<Paseto.Builder> pasetoV1Builders() {
		return Stream.of(
				new PasetoV1.Builder()
						.withEncodingProvider(new JacksonJsonProvider())
						.withName("v1/jackson"),
				new PasetoV1.Builder()
						.withEncodingProvider(new GsonJsonProvider())
						.withName("v1/gson")
		);
	}

	static Stream<Paseto.Builder> pasetoV2Builders() {
		return Stream.of(
				// BouncyCastle
				new PasetoV2.Builder()
						.withV2CryptoProvider(new BouncyCastleV2CryptoProvider())
						.withEncodingProvider(new JacksonJsonProvider())
						.withName("v2/bc/jackson"),
				new PasetoV2.Builder()
						.withV2CryptoProvider(new BouncyCastleV2CryptoProvider())
						.withEncodingProvider(new GsonJsonProvider())
						.withName("v2/bc/gson")
		);
	}

	static Stream<Paseto.Builder> pasetoV4Builders() {
		return Stream.of(
				// BouncyCastle
				new PasetoV4.Builder()
						.withV4CryptoProvider(new BouncyCastleV4CryptoProvider())
						.withEncodingProvider(new JacksonJsonProvider())
						.withName("v4/bc/jackson"),
				new PasetoV4.Builder()
						.withV4CryptoProvider(new BouncyCastleV4CryptoProvider())
						.withEncodingProvider(new GsonJsonProvider())
						.withName("v4/bc/gson")
		);
	}

	static Stream<V1CryptoProvider> v1CryptoProviders() {
		return Stream.of(
				new NamedBouncyCastleV1CryptoProvider()
		);
	}

	static Stream<V2CryptoProvider> v2CryptoProviders() {
		return Stream.of(
				new NamedBouncyCastleV2CryptoProvider()
		);
	}

	static Stream<V4CryptoProvider> v4CryptoProviders() {
		return Stream.of(
				new NamedBouncyCastleV4CryptoProvider()
		);
	}

	private static class NamedBouncyCastleV1CryptoProvider extends BouncyCastleV1CryptoProvider {
		@Override
		public String toString() {
			return "v1/bc";
		}
	}

	private static class NamedBouncyCastleV2CryptoProvider extends BouncyCastleV2CryptoProvider {
		@Override
		public String toString() {
			return "v2/bc";
		}
	}

	private static class NamedBouncyCastleV4CryptoProvider extends BouncyCastleV4CryptoProvider {
		@Override
		public String toString() {
			return "v4/bc";
		}
	}
}
