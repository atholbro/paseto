package net.aholbrook.paseto

import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import net.aholbrook.paseto.crypto.withTestNonce
import net.aholbrook.paseto.protocol.AsymmetricPublicKey
import net.aholbrook.paseto.protocol.AsymmetricSecretKey
import net.aholbrook.paseto.protocol.KeyPair
import net.aholbrook.paseto.protocol.SymmetricKey
import net.aholbrook.paseto.protocol.Version
import net.aholbrook.paseto.rules.rules
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.stream.Stream

private val json = Json {
    explicitNulls = false
    ignoreUnknownKeys = false
}

private fun loadServiceVectors(resourcePath: String): ServiceTestVectors = ServiceTestVectorsTests::class.java.getResourceAsStream(resourcePath)!!.use { inputStream ->
    json.decodeFromString<ServiceTestVectors>(inputStream.readAllBytes().toString(Charsets.UTF_8))
}

private fun Version.serviceTestFile(): String = "/service-test-vectors/${this.toString().lowercase()}.json"

private fun localService(version: Version, vector: ServiceTestVector, currentTime: Instant?): TokenService {
    val clock = currentTime?.let { Clock.fixed(it, ZoneOffset.UTC) }

    return tokenService(version, Purpose.Local { SymmetricKey.ofHex(vector.key!!, version) }) {
        rules = rules {
            issuedInPast = clock?.let { issuedInPast?.copy(clock = clock) }
            notExpired = clock?.let { notExpired?.copy(clock = clock) }
        }
    }
}

private fun publicService(version: Version, vector: ServiceTestVector, currentTime: Instant?): TokenService {
    val clock = currentTime?.let { Clock.fixed(it, ZoneOffset.UTC) }

    return tokenService(
        version,
        Purpose.Public {
            if (version == Version.V1) {
                KeyPair(
                    AsymmetricSecretKey.ofPem(vector.secretKey!!, version),
                    AsymmetricPublicKey.ofPem(vector.publicKey!!, version),
                )
            } else {
                KeyPair(
                    AsymmetricSecretKey.ofHex(vector.secretKey!!, version),
                    AsymmetricPublicKey.ofHex(vector.publicKey!!, version),
                )
            }
        },
    ) {
        rules = rules {
            issuedInPast = clock?.let { issuedInPast?.copy(clock = clock) }
            notExpired = clock?.let { notExpired?.copy(clock = clock) }
        }
    }
}

class ServiceTestVectorsTests {
    @ParameterizedTest(name = "{0}")
    @MethodSource("loadServiceVectorTests")
    fun serviceVectorTest(
        name: String,
        version: Version,
        vector: ServiceTestVector,
        test: (version: Version, vector: ServiceTestVector) -> Unit,
    ) {
        withTestNonce(vector.nonce?.let { Hex.decode(it) }) {
            test(version, vector)
        }
    }

    companion object {
        private fun encodeTest(version: Version, vector: ServiceTestVector) {
            val expected = tokenFromVector(vector)
            val currentTime = expected.notBefore ?: expected.issuedAt

            val actual = when (vector.mode) {
                "local" -> localService(version, vector, currentTime).encode(expected)
                "public" -> publicService(version, vector, currentTime).encode(expected)
                else -> error("Unsupported mode: ${vector.mode}")
            }

            if (version == Version.V1 && vector.mode == "public") {
                val decoded = publicService(version, vector, currentTime)
                    .decode(actual, expected.footer)
                decoded shouldBe expected
            } else {
                actual shouldBe vector.token
            }
        }

        private fun decodeTest(version: Version, vector: ServiceTestVector) {
            val expected = tokenFromVector(vector)
            val currentTime = expected.notBefore ?: expected.issuedAt

            val actual = when (vector.mode) {
                "local" -> localService(version, vector, currentTime)
                    .decode(vector.token, expected.footer)

                "public" -> publicService(version, vector, currentTime)
                    .decode(vector.token, expected.footer)

                else -> error("Unsupported mode: ${vector.mode}")
            }

            actual shouldBe expected
        }

        @JvmStatic
        fun loadServiceVectorTests(): Stream<Arguments> = Version.entries
            .flatMap { version ->
                val file = version.serviceTestFile()
                val vectors = loadServiceVectors(file)
                vectors.tests.flatMap { vector ->
                    listOf(
                        Arguments.of(
                            "${vectors.name} - ${vector.name}: encode",
                            version,
                            vector,
                            ::encodeTest,
                        ),
                        Arguments.of(
                            "${vectors.name} - ${vector.name}: decode",
                            version,
                            vector,
                            ::decodeTest,
                        ),
                    )
                }
            }.stream()
    }
}
