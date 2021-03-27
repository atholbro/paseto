package net.aholbrook.paseto;

import net.aholbrook.paseto.crypto.v1.V1CryptoProvider;
import net.aholbrook.paseto.crypto.v1.bc.BouncyCastleV1CryptoProvider;
import net.aholbrook.paseto.crypto.v2.V2CryptoProvider;
import net.aholbrook.paseto.crypto.v2.bc.BouncyCastleV2CryptoProvider;
import net.aholbrook.paseto.crypto.v2.libsodium.LibSodiumV2CryptoProvider;
import net.aholbrook.paseto.encoding.EncodingProvider;
import net.aholbrook.paseto.encoding.json.gson.GsonJsonProvider;
import net.aholbrook.paseto.encoding.json.jackson.JacksonJsonProvider;

import java.util.stream.Stream;

public class Sources {
	private Sources() {}

	static Stream<EncodingProvider> encodingProviders() {
		return Stream.of(new JacksonJsonProvider(), new GsonJsonProvider());
	}

	static Stream<Paseto.Builder> pasetoV1Builders() {
		return Stream.of(
				new PasetoV1.Builder().withEncodingProvider(new JacksonJsonProvider()),
				new PasetoV1.Builder().withEncodingProvider(new GsonJsonProvider())
		);
	}

	static Stream<Paseto.Builder> pasetoV2Builders() {
		return Stream.of(
				// BouncyCastle
				new PasetoV2.Builder()
						.withV2CryptoProvider(new BouncyCastleV2CryptoProvider())
						.withEncodingProvider(new JacksonJsonProvider()),
				new PasetoV2.Builder()
						.withV2CryptoProvider(new BouncyCastleV2CryptoProvider())
						.withEncodingProvider(new GsonJsonProvider()),

				// LibSodium
				new PasetoV2.Builder()
						.withV2CryptoProvider(new LibSodiumV2CryptoProvider())
						.withEncodingProvider(new JacksonJsonProvider()),
				new PasetoV2.Builder()
						.withV2CryptoProvider(new LibSodiumV2CryptoProvider())
						.withEncodingProvider(new GsonJsonProvider())
		);
	}

	static Stream<V1CryptoProvider> v1CryptoProviders() {
		return Stream.of(
				new BouncyCastleV1CryptoProvider()
		);
	}

	static Stream<V2CryptoProvider> v2CryptoProviders() {
		return Stream.of(
				new BouncyCastleV2CryptoProvider(),
				new LibSodiumV2CryptoProvider()
		);
	}
}
