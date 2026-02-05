package net.aholbrook.paseto.protocol

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.aholbrook.paseto.crypto.withTestNonce
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream

@Serializable
data class TestVectors(
    val name: String,
    val tests: List<TestVector>,
)

@Serializable
data class TestVector(
    val name: String,
    @SerialName("expect-fail")
    val expectFail: Boolean,

    val nonce: String? = null,
    val key: String? = null,

    @SerialName("public-key")
    val publicKey: String? = null,
    @SerialName("secret-key")
    val secretKey: String? = null,
    @SerialName("public-key-pem")
    val publicKeyPem: String? = null,
    @SerialName("secret-key-pem")
    val secretKeyPem: String? = null,
    @SerialName("secret-key-seed")
    val secretKeySeed: String? = null,

    val token: String,
    val payload: String? = null,
    val footer: String,

    @SerialName("implicit-assertion")
    val implicitAssertion: String,
)

private val json = Json {
    explicitNulls = false
    ignoreUnknownKeys = false
}

private fun Version.testFile() = when(this) {
    Version.V1 -> "/v1.json"
    Version.V2 -> "/v2.json"
    Version.V3 -> "/v3.json"
    Version.V4 -> "/v4.json"
}

private fun loadVectors(resourcePath: String): TestVectors {
    return TestVectorsTests::class.java.getResourceAsStream(resourcePath)!!.use { inputStream ->
        json.decodeFromString<TestVectors>(inputStream.readAllBytes().toString(Charsets.UTF_8))
    }
}

class TestVectorsTests {
    @ParameterizedTest(name = "{0}")
    @MethodSource("loadJsonVectors")
    fun testVector(
        name: String,
        version: Version,
        vector: TestVector,
        test: (paseto: Paseto, vector: TestVector) -> Unit
    ) {
        val paseto = version.paseto

        withTestNonce(vector.nonce?.let { Hex.decode(it) }) {
            if (vector.expectFail) {
                shouldThrow<Exception> { test(paseto, vector) }
            } else {
                test(paseto, vector)
            }
        }
    }

    companion object {
        private fun testPemLoadingPublicKey(paseto: Paseto, vector: TestVector) {
            val pemKey = AsymmetricPublicKey.ofPem(vector.publicKeyPem!!, paseto.version)
            val hexKey = AsymmetricPublicKey.ofHex(vector.publicKey!!, paseto.version)
            pemKey shouldBe hexKey
        }

        private fun testPemLoadingSecretKey(paseto: Paseto, vector: TestVector) {
            val pemKey = AsymmetricSecretKey.ofPem(vector.secretKeyPem!!, paseto.version)
            val hexKey = AsymmetricSecretKey.ofHex(vector.secretKey!!, paseto.version)
            pemKey shouldBe hexKey
        }

        private fun testEncrypt(paseto: Paseto, vector: TestVector) {
            val actual = paseto.encrypt(
                payload = vector.payload!!,
                key = SymmetricKey.ofHex(vector.key!!, paseto.version),
                footer = vector.footer,
                implicitAssertion = vector.implicitAssertion,
            )
            actual shouldBe vector.token
        }

        private fun testDecrypt(paseto: Paseto, vector: TestVector) {
            val actual = paseto.decrypt(
                token = vector.token,
                key = SymmetricKey.ofHex(vector.key!!, paseto.version),
                footer = vector.footer,
                implicitAssertion = vector.implicitAssertion,
            )
            actual shouldBe vector.payload
        }

        private fun testSign(paseto: Paseto, vector: TestVector) {
            val key = if (paseto.version == Version.V1) {
                AsymmetricSecretKey.ofPem(vector.secretKey!!, paseto.version)
            } else {
                AsymmetricSecretKey.ofHex(vector.secretKey!!, paseto.version)
            }

            val signed = paseto.sign(
                payload = vector.payload!!,
                secretKey = key,
                footer = vector.footer,
                implicitAssertion = vector.implicitAssertion
            )

            // V1/V3 signatures are non-deterministic
            when (paseto.version) {
                Version.V1-> {
                    val publicKey = AsymmetricPublicKey.ofPem(vector.publicKey!!, paseto.version)
                    val actual = paseto.verify(signed, publicKey, vector.footer, vector.implicitAssertion)
                    actual shouldBe vector.payload
                }

                Version.V3 -> {
                    val publicKey = AsymmetricPublicKey.ofHex(vector.publicKey!!, paseto.version)
                    val actual = paseto.verify(signed, publicKey, vector.footer, vector.implicitAssertion)
                    actual shouldBe vector.payload
                }

                else -> {
                    signed shouldBe vector.token
                }
            }
        }

        private fun testVerify(paseto: Paseto, vector: TestVector) {
            val key = if (paseto.version == Version.V1) {
                AsymmetricPublicKey.ofPem(vector.publicKey!!, paseto.version)
            } else {
                AsymmetricPublicKey.ofHex(vector.publicKey!!, paseto.version)
            }

            val actual = paseto.verify(
                token = vector.token,
                publicKey = key,
                footer = vector.footer,
                implicitAssertion = vector.implicitAssertion
            )
            actual shouldBe vector.payload
        }

        @JvmStatic
        fun loadJsonVectors(): Stream<Arguments> {
            return listOf(Version.V1, Version.V2, Version.V3, Version.V4)
                .flatMap { version ->
                    val vectors = loadVectors(version.testFile())
                    vectors.tests.flatMap { vector ->
                        listOfNotNull(
                            Arguments.of(
                                "${vectors.name} - ${vector.name}: pem loading public key",
                                version,
                                vector,
                                ::testPemLoadingPublicKey
                            ).takeIf { !vector.expectFail && vector.publicKeyPem != null && vector.publicKey != null },

                            // protocol
                            Arguments.of(
                                "${vectors.name} - ${vector.name}: pem loading secret key",
                                version,
                                vector,
                                ::testPemLoadingSecretKey
                            ).takeIf { !vector.expectFail && vector.secretKeyPem != null && vector.secretKey != null },

                            Arguments.of(
                                "${vectors.name} - ${vector.name}: encrypt",
                                version,
                                vector,
                                ::testEncrypt
                            ).takeIf { vector.key != null },

                            Arguments.of(
                                "${vectors.name} - ${vector.name}: decrypt",
                                version,
                                vector,
                                ::testDecrypt
                            ).takeIf { vector.key != null },

                            Arguments.of(
                                "${vectors.name} - ${vector.name}: sign",
                                version,
                                vector,
                                ::testSign
                            ).takeIf { vector.secretKey != null },

                            Arguments.of(
                                "${vectors.name} - ${vector.name}: verify",
                                version,
                                vector,
                                ::testVerify
                            ).takeIf { vector.publicKey != null },
                        )
                    }
                }.stream()
        }
    }
}
