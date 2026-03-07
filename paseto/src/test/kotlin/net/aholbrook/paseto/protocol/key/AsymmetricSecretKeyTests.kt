package net.aholbrook.paseto.protocol.key

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.mockk.every
import io.mockk.mockk
import net.aholbrook.paseto.exception.KeyLengthException
import net.aholbrook.paseto.exception.KeyPemUnsupportedTypeException
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyReuseException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.keyV1Public
import net.aholbrook.paseto.keyV4Public
import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.Version
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.io.encoding.Base64

class AsymmetricSecretKeyTests {
    companion object {
        @JvmStatic
        fun allVersions(): Stream<Arguments> = listOf(
            Version.V1,
            Version.V2,
            Version.V3,
            Version.V4,
        ).map { Arguments.of(it) }.stream()
    }

    @Test
    fun `AsymmetricSecretKey enforces key lengths`() {
        shouldThrow<KeyLengthException> {
            AsymmetricSecretKey.ofHex("0".repeat(10), Version.V4)
        }
    }

    @Test
    fun `AsymmetricSecretKey enforces version match on getKeyMaterialFor`() {
        shouldThrow<KeyVersionException> {
            keyV4Public.secretKey!!.getKeyMaterialFor(Version.V2, Purpose.PUBLIC)
        }
    }

    @Test
    fun `AsymmetricSecretKey enforces purpose match on getKeyMaterialFor`() {
        shouldThrow<KeyPurposeException> {
            keyV4Public.secretKey!!.getKeyMaterialFor(Version.V4, Purpose.LOCAL)
        }
    }

    @Test
    fun `AsymmetricSecretKey equals and hashCode`() {
        val key = AsymmetricSecretKey.ofHex("0".repeat(64), Version.V4)

        key shouldBe key
        key shouldNotBe null
        key.hashCode() shouldBe key.hashCode()
        key shouldNotBe ""
        key shouldBe AsymmetricSecretKey.ofHex("0".repeat(64), Version.V4)
        key shouldNotBe AsymmetricSecretKey.ofHex("0".repeat(64), Version.V2)
        key.hashCode() shouldNotBe AsymmetricSecretKey.ofHex("0".repeat(64), Version.V2).hashCode()
        key shouldNotBe AsymmetricSecretKey.ofHex("1".repeat(64), Version.V4)
        key.hashCode() shouldNotBe AsymmetricSecretKey.ofHex("1".repeat(64), Version.V4).hashCode()

        val wrongPurpose = mockk<AsymmetricSecretKey>()
        every { wrongPurpose.version } returns key.version
        every { wrongPurpose.purpose } returns Purpose.LOCAL
        key shouldNotBe wrongPurpose

        // normalization of secret key (removes public key for comparison)
        key shouldBe AsymmetricSecretKey.ofHex("0".repeat(128), Version.V4)
        key.hashCode() shouldBe AsymmetricSecretKey.ofHex("0".repeat(128), Version.V4).hashCode()

        // verify normalizeMaterial does not impact V1
        keyV1Public.secretKey shouldBe AsymmetricSecretKey.ofRawBytes(
            keyV1Public.secretKey!!.getKeyMaterialFor(Version.V1, Purpose.PUBLIC),
            Version.V1,
        )
    }

    @Test
    fun asymmetricSecretKey_ofBase64Url() {
        val b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val key = AsymmetricSecretKey.ofBase64Url(b64, Version.V4)
        key.getKeyMaterialFor(Version.V4, Purpose.PUBLIC) contentEquals Base64.UrlSafe.decode(b64)
    }

    @ParameterizedTest
    @MethodSource("allVersions")
    fun asymmetricSecretKey_pemUnsupportedType(version: Version) {
        val pem = """
            -----BEGIN CORRUPT PRIVATE KEY-----
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            -----END CORRUPT PRIVATE KEY-----
        """.trimIndent()

        val ex = shouldThrow<KeyPemUnsupportedTypeException> {
            AsymmetricSecretKey.ofPem(pem, version)
        }
        ex.type shouldBe "CORRUPT PRIVATE KEY"
    }

    @Test
    fun `AsymmetricSecretKey toHex throws KeyReuseException after clear`() {
        val key = keyV4Public.secretKey!!
        key.clear()
        shouldThrow<KeyReuseException> { key.toHex() }
    }

    @Test
    fun `AsymmetricSecretKey toBase64Url throws KeyReuseException after clear`() {
        val key = keyV4Public.secretKey!!
        key.clear()
        shouldThrow<KeyReuseException> { key.toBase64Url() }
    }

    @Test
    fun `AsymmetricSecretKey toPem throws KeyReuseException after clear`() {
        val key = keyV4Public.secretKey!!
        key.clear()
        shouldThrow<KeyReuseException> { key.toPem() }
    }

    @Test
    fun `AsymmetricSecretKey getKeyMaterialFor throws KeyReuseException after clear`() {
        val key = keyV4Public.secretKey!!
        key.clear()
        shouldThrow<KeyReuseException> { key.getKeyMaterialFor(Version.V4, Purpose.PUBLIC) }
    }

    @ParameterizedTest
    @MethodSource("allVersions")
    fun asymmetricSecretKey_canSaveHex(version: Version) {
        val key = KeyPair.generate(version)
        val saved = key.secretKey!!.toHex()
        val loaded = AsymmetricSecretKey.ofHex(saved, version)

        loaded shouldBe key.secretKey
    }

    @ParameterizedTest
    @MethodSource("allVersions")
    fun asymmetricSecretKey_canSaveBase64Url(version: Version) {
        val key = KeyPair.generate(version)
        val saved = key.secretKey!!.toBase64Url()
        val loaded = AsymmetricSecretKey.ofBase64Url(saved, version)

        loaded shouldBe key.secretKey
    }

    @ParameterizedTest
    @MethodSource("allVersions")
    fun asymmetricSecretKey_canSavePem(version: Version) {
        val key = KeyPair.generate(version)
        val saved = key.secretKey!!.toPem()
        val loaded = AsymmetricSecretKey.ofPem(saved, version)

        loaded shouldBe key.secretKey
    }
}
