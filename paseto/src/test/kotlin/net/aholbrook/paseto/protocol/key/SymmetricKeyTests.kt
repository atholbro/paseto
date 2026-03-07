package net.aholbrook.paseto.protocol.key

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.mockk.every
import io.mockk.mockk
import net.aholbrook.paseto.exception.KeyLengthException
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyReuseException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.keyV1Public
import net.aholbrook.paseto.keyV2Public
import net.aholbrook.paseto.keyV3Public
import net.aholbrook.paseto.keyV4Local
import net.aholbrook.paseto.keyV4Public
import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.Version
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.io.encoding.Base64

class SymmetricKeyTests {
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
    fun `SymmetricKey enforces key lengths`() {
        shouldThrow<KeyLengthException> {
            SymmetricKey.ofHex("0".repeat(10), Version.V4)
        }
    }

    @Test
    fun `SymmetricKey enforces version match on getKeyMaterialFor`() {
        shouldThrow<KeyVersionException> {
            keyV4Local.getKeyMaterialFor(Version.V2, Purpose.LOCAL)
        }
    }

    @Test
    fun `SymmetricKey enforces purpose match on getKeyMaterialFor`() {
        shouldThrow<KeyPurposeException> {
            keyV4Local.getKeyMaterialFor(Version.V4, Purpose.PUBLIC)
        }
    }

    @Test
    fun `SymmetricKey equals and hashCode`() {
        val key = SymmetricKey.ofHex("0".repeat(64), Version.V4)

        key shouldBe key
        key shouldNotBe null
        key.hashCode() shouldBe key.hashCode()
        key shouldNotBe ""
        key shouldBe SymmetricKey.ofHex("0".repeat(64), Version.V4)
        key shouldNotBe SymmetricKey.ofHex("0".repeat(64), Version.V2)
        key.hashCode() shouldNotBe SymmetricKey.ofHex("0".repeat(64), Version.V2).hashCode()
        key shouldNotBe SymmetricKey.ofHex("1".repeat(64), Version.V4)
        key.hashCode() shouldNotBe SymmetricKey.ofHex("1".repeat(64), Version.V4).hashCode()

        val wrongPurpose = mockk<SymmetricKey>()
        every { wrongPurpose.version } returns key.version
        every { wrongPurpose.purpose } returns Purpose.LOCAL
        key shouldNotBe wrongPurpose
    }

    @Test
    fun symmetricKey_ofBase64Url() {
        val b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val key = SymmetricKey.ofBase64Url(b64, Version.V4)
        key.getKeyMaterialFor(Version.V4, Purpose.LOCAL) contentEquals Base64.UrlSafe.decode(b64)
    }

    @Test
    fun `SymmetricKey toHex throws KeyReuseException after clear`() {
        val key = keyV4Local
        key.clear()
        shouldThrow<KeyReuseException> { key.toHex() }
    }

    @Test
    fun `SymmetricKey toBase64Url throws KeyReuseException after clear`() {
        val key = keyV4Local
        key.clear()
        shouldThrow<KeyReuseException> { key.toBase64Url() }
    }

    @Test
    fun `SymmetricKey getKeyMaterialFor throws KeyReuseException after clear`() {
        val key = keyV4Local
        key.clear()
        shouldThrow<KeyReuseException> { key.getKeyMaterialFor(Version.V4, Purpose.LOCAL) }
    }

    @ParameterizedTest
    @MethodSource("allVersions")
    fun symmetricKey_canSaveHex(version: Version) {
        val key = SymmetricKey.generate(version)
        val saved = key.toHex()
        val loaded = SymmetricKey.ofHex(saved, version)

        loaded shouldBe key
    }

    @ParameterizedTest
    @MethodSource("allVersions")
    fun symmetricKey_canSaveBase64Url(version: Version) {
        val key = SymmetricKey.generate(version)
        val saved = key.toBase64Url()
        val loaded = SymmetricKey.ofBase64Url(saved, version)

        loaded shouldBe key
    }
}
