package net.aholbrook.paseto.protocol.key

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.mockk.every
import io.mockk.mockk
import net.aholbrook.paseto.exception.KeyLengthException
import net.aholbrook.paseto.exception.KeyPemUnsupportedTypeException
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.keyV1Public
import net.aholbrook.paseto.keyV2Public
import net.aholbrook.paseto.keyV3Public
import net.aholbrook.paseto.keyV4Public
import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.Version
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.io.encoding.Base64

class AsymmetricPublicKeyTests {
    companion object {
        @JvmStatic
        fun keyPairsAllVersions(): Stream<Arguments> = listOf(
            keyV1Public,
            keyV2Public,
            keyV3Public,
            keyV4Public,
        ).map { Arguments.of(it) }.stream()

        @JvmStatic
        fun allVersions(): Stream<Arguments> = listOf(
            Version.V1,
            Version.V2,
            Version.V3,
            Version.V4,
        ).map { Arguments.of(it) }.stream()
    }

    @ParameterizedTest
    @MethodSource("keyPairsAllVersions")
    fun `AsymmetricPublicKey can be recovered from AsymmetricSecretKey`(keyPair: KeyPair) {
        AsymmetricPublicKey.fromSecretKey(keyPair.secretKey!!) shouldBe keyPair.publicKey
    }

    @Test
    fun `AsymmetricPublicKey enforces key lengths`() {
        val ex = shouldThrow<KeyLengthException> {
            AsymmetricPublicKey.ofHex("0".repeat(10), Version.V4)
        }
        ex.actual shouldBe 5
        ex.allowed shouldBe arrayOf(32)
    }

    @Test
    fun `AsymmetricPublicKey enforces version match on getKeyMaterialFor`() {
        val ex = shouldThrow<KeyVersionException> {
            keyV4Public.publicKey.getKeyMaterialFor(Version.V2, Purpose.PUBLIC)
        }
        ex.expected shouldBe Version.V2
        ex.actual shouldBe Version.V4
    }

    @Test
    fun `AsymmetricPublicKey enforces purpose match on getKeyMaterialFor`() {
        val ex = shouldThrow<KeyPurposeException> {
            keyV4Public.publicKey.getKeyMaterialFor(Version.V4, Purpose.LOCAL)
        }
        ex.expected shouldBe "LOCAL"
        ex.actual shouldBe "PUBLIC"
    }

    @Test
    fun `AsymmetricPublicKey equals and hashCode`() {
        val key = AsymmetricPublicKey.ofHex("0".repeat(64), Version.V4)

        key shouldBe key
        key shouldNotBe null
        key.hashCode() shouldBe key.hashCode()
        key shouldNotBe ""
        key shouldBe AsymmetricPublicKey.ofHex("0".repeat(64), Version.V4)
        key shouldNotBe AsymmetricPublicKey.ofHex("0".repeat(64), Version.V2)
        key.hashCode() shouldNotBe AsymmetricPublicKey.ofHex("0".repeat(64), Version.V2).hashCode()
        key shouldNotBe AsymmetricPublicKey.ofHex("1".repeat(64), Version.V4)
        key.hashCode() shouldNotBe AsymmetricPublicKey.ofHex("1".repeat(64), Version.V4).hashCode()

        val wrongPurpose = mockk<AsymmetricPublicKey>()
        every { wrongPurpose.version } returns key.version
        every { wrongPurpose.purpose } returns Purpose.LOCAL
        key shouldNotBe wrongPurpose
    }

    @Test
    fun asymmetricPublicKey_ofBase64Url() {
        val b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val key = AsymmetricPublicKey.ofBase64Url(b64, Version.V4)
        key.getKeyMaterialFor(Version.V4, Purpose.PUBLIC) contentEquals Base64.UrlSafe.decode(b64)
    }

    @ParameterizedTest
    @MethodSource("allVersions")
    fun asymmetricPublicKey_pemUnsupportedType(version: Version) {
        val pem = """
            -----BEGIN CORRUPT PUBLIC KEY-----
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            -----END CORRUPT PUBLIC KEY-----
        """.trimIndent()

        val ex = shouldThrow<KeyPemUnsupportedTypeException> {
            AsymmetricPublicKey.ofPem(pem, version)
        }
        ex.type shouldBe "CORRUPT PUBLIC KEY"
    }

    @ParameterizedTest
    @MethodSource("allVersions")
    fun asymmetricPublicKey_canSaveHex(version: Version) {
        val key = KeyPair.generate(version)
        val saved = key.publicKey.toHex()
        val loaded = AsymmetricPublicKey.ofHex(saved, version)

        loaded shouldBe key.publicKey
    }

    @ParameterizedTest
    @MethodSource("allVersions")
    fun asymmetricPublicKey_canSaveBase64Url(version: Version) {
        val key = KeyPair.generate(version)
        val saved = key.publicKey.toBase64Url()
        val loaded = AsymmetricPublicKey.ofBase64Url(saved, version)

        loaded shouldBe key.publicKey
    }

    @ParameterizedTest
    @MethodSource("allVersions")
    fun asymmetricPublicKey_canSavePem(version: Version) {
        val key = KeyPair.generate(version)
        val saved = key.publicKey.toPem()
        val loaded = AsymmetricPublicKey.ofPem(saved, version)

        loaded shouldBe key.publicKey
    }
}
