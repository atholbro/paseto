package net.aholbrook.paseto.protocol.key

import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.mockk.every
import io.mockk.mockk
import net.aholbrook.paseto.exception.KeyClearedException
import net.aholbrook.paseto.exception.KeyLengthException
import net.aholbrook.paseto.exception.KeyPemUnsupportedTypeException
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.keyV1Public
import net.aholbrook.paseto.keyV4Public
import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.Version
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.EnumSource
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

        @JvmStatic
        fun allVersionsWithLifecycle(): Stream<Arguments> = listOf(
            Pair(Version.V1, KeyLifecycle.PERSISTENT),
            Pair(Version.V1, KeyLifecycle.EPHEMERAL),
            Pair(Version.V2, KeyLifecycle.PERSISTENT),
            Pair(Version.V2, KeyLifecycle.EPHEMERAL),
            Pair(Version.V3, KeyLifecycle.PERSISTENT),
            Pair(Version.V3, KeyLifecycle.EPHEMERAL),
            Pair(Version.V4, KeyLifecycle.PERSISTENT),
            Pair(Version.V4, KeyLifecycle.EPHEMERAL),
        ).map { Arguments.of(it.first, it.second) }.stream()
    }

    @Test
    fun `AsymmetricSecretKey enforces key lengths`() {
        val ex = shouldThrow<KeyLengthException> {
            AsymmetricSecretKey.ofHex("0".repeat(10), Version.V4)
        }
        ex.actual shouldBe 5
        ex.allowed shouldBe arrayOf(64, 32)
    }

    @Test
    fun `AsymmetricSecretKey enforces version match on getKeyMaterialFor`() {
        val ex = shouldThrow<KeyVersionException> {
            keyV4Public.secretKey!!.getKeyMaterialFor(Version.V2, Purpose.PUBLIC)
        }
        ex.expected shouldBe Version.V2
        ex.actual shouldBe Version.V4
    }

    @Test
    fun `AsymmetricSecretKey enforces purpose match on getKeyMaterialFor`() {
        val ex = shouldThrow<KeyPurposeException> {
            keyV4Public.secretKey!!.getKeyMaterialFor(Version.V4, Purpose.LOCAL)
        }
        ex.expected shouldBe "LOCAL"
        ex.actual shouldBe "PUBLIC"
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
    fun `AsymmetricSecretKey toHex throws KeyClearedException after clear`() {
        val key = keyV4Public.secretKey!!.copy()
        key.clear()
        shouldThrow<KeyClearedException> { key.toHex() }
    }

    @Test
    fun `AsymmetricSecretKey toBase64Url throws KeyClearedException after clear`() {
        val key = keyV4Public.secretKey!!.copy()
        key.clear()
        shouldThrow<KeyClearedException> { key.toBase64Url() }
    }

    @Test
    fun `AsymmetricSecretKey toPem throws KeyClearedException after clear`() {
        val key = keyV4Public.secretKey!!.copy()
        key.clear()
        shouldThrow<KeyClearedException> { key.toPem() }
    }

    @Test
    fun `AsymmetricSecretKey getKeyMaterialFor throws KeyClearedException after clear`() {
        val key = keyV4Public.secretKey!!.copy()
        key.clear()
        shouldThrow<KeyClearedException> { key.getKeyMaterialFor(Version.V4, Purpose.PUBLIC) }
    }

    @ParameterizedTest
    @EnumSource(KeyLifecycle::class)
    fun `AsymmetricSecretKey internalClear respects lifecycle`(lifecycle: KeyLifecycle) {
        val key = keyV4Public.secretKey!!.copy(lifecycle)
        try {
            key.internalClear()

            when (lifecycle) {
                KeyLifecycle.PERSISTENT ->
                    shouldNotThrow<KeyClearedException> { key.getKeyMaterialFor(Version.V4, Purpose.PUBLIC) }

                KeyLifecycle.EPHEMERAL ->
                    shouldThrow<KeyClearedException> { key.getKeyMaterialFor(Version.V4, Purpose.PUBLIC) }
            }
        } finally {
            key.clear()
        }
    }

    @ParameterizedTest
    @MethodSource("allVersionsWithLifecycle")
    fun asymmetricSecretKey_canSaveLoadBytes(version: Version, lifecycle: KeyLifecycle) {
        val key = KeyPair.generate(version)
        val saved = key.secretKey!!.getKeyMaterialFor(key.version, Purpose.PUBLIC)
        val loaded = AsymmetricSecretKey.ofRawBytes(saved, version, lifecycle)

        loaded shouldBe key.secretKey
        loaded.lifecycle shouldBe lifecycle
        loaded.clear()
    }

    @ParameterizedTest
    @MethodSource("allVersionsWithLifecycle")
    fun asymmetricSecretKey_canSaveLoadHex(version: Version, lifecycle: KeyLifecycle) {
        val key = KeyPair.generate(version)
        val saved = key.secretKey!!.toHex()
        val loaded = AsymmetricSecretKey.ofHex(saved, version, lifecycle)

        loaded shouldBe key.secretKey
        loaded.lifecycle shouldBe lifecycle
        loaded.clear()
    }

    @ParameterizedTest
    @MethodSource("allVersionsWithLifecycle")
    fun asymmetricSecretKey_canSaveLoadBase64Url(version: Version, lifecycle: KeyLifecycle) {
        val key = KeyPair.generate(version)
        val saved = key.secretKey!!.toBase64Url()
        val loaded = AsymmetricSecretKey.ofBase64Url(saved, version, lifecycle)

        loaded shouldBe key.secretKey
        loaded.lifecycle shouldBe lifecycle
        loaded.clear()
    }

    @ParameterizedTest
    @MethodSource("allVersionsWithLifecycle")
    fun asymmetricSecretKey_canSaveLoadPem(version: Version, lifecycle: KeyLifecycle) {
        val key = KeyPair.generate(version)
        val saved = key.secretKey!!.toPem()
        val loaded = AsymmetricSecretKey.ofPem(saved, version, lifecycle)

        loaded shouldBe key.secretKey
        loaded.lifecycle shouldBe lifecycle
        loaded.clear()
    }
}
