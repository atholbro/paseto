package net.aholbrook.paseto.protocol.key

import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.mockk.every
import io.mockk.mockk
import net.aholbrook.paseto.exception.KeyClearedException
import net.aholbrook.paseto.exception.KeyLengthException
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.keyV4Local
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

class SymmetricKeyTests {
    companion object {
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
    fun `SymmetricKey enforces key lengths`() {
        val ex = shouldThrow<KeyLengthException> {
            SymmetricKey.ofHex("0".repeat(10), Version.V4)
        }
        ex.actual shouldBe 5
        ex.allowed shouldBe arrayOf(32)
    }

    @Test
    fun `SymmetricKey enforces version match on getKeyMaterialFor`() {
        val ex = shouldThrow<KeyVersionException> {
            keyV4Local.getKeyMaterialFor(Version.V2, Purpose.LOCAL)
        }
        ex.expected shouldBe Version.V2
        ex.actual shouldBe Version.V4
    }

    @Test
    fun `SymmetricKey enforces purpose match on getKeyMaterialFor`() {
        val ex = shouldThrow<KeyPurposeException> {
            keyV4Local.getKeyMaterialFor(Version.V4, Purpose.PUBLIC)
        }
        ex.expected shouldBe "PUBLIC"
        ex.actual shouldBe "LOCAL"
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
    fun `SymmetricKey toHex throws KeyClearedException after clear`() {
        val key = keyV4Local.copy()
        key.clear()
        shouldThrow<KeyClearedException> { key.toHex() }
    }

    @Test
    fun `SymmetricKey toBase64Url throws KeyClearedException after clear`() {
        val key = keyV4Local.copy()
        key.clear()
        shouldThrow<KeyClearedException> { key.toBase64Url() }
    }

    @Test
    fun `SymmetricKey getKeyMaterialFor throws KeyClearedException after clear`() {
        val key = keyV4Local.copy()
        key.clear()
        shouldThrow<KeyClearedException> { key.getKeyMaterialFor(Version.V4, Purpose.LOCAL) }
    }

    @ParameterizedTest
    @EnumSource(KeyLifecycle::class)
    fun `SymmetricKey internalClear respects lifecycle`(lifecycle: KeyLifecycle) {
        val key = keyV4Local.copy(lifecycle)
        try {
            key.internalClear()

            when (lifecycle) {
                KeyLifecycle.PERSISTENT ->
                    shouldNotThrow<KeyClearedException> { key.getKeyMaterialFor(Version.V4, Purpose.LOCAL) }

                KeyLifecycle.EPHEMERAL ->
                    shouldThrow<KeyClearedException> { key.getKeyMaterialFor(Version.V4, Purpose.LOCAL) }
            }
        } finally {
            key.clear()
        }
    }

    @ParameterizedTest
    @MethodSource("allVersionsWithLifecycle")
    fun symmetricKey_canSaveLoadBytes(version: Version, lifecycle: KeyLifecycle) {
        val key = SymmetricKey.generate(version)
        val saved = key.getKeyMaterialFor(version, Purpose.LOCAL)
        val loaded = SymmetricKey.ofRawBytes(saved, version, lifecycle)

        loaded shouldBe key
        loaded.lifecycle shouldBe lifecycle
        loaded.clear()
    }

    @ParameterizedTest
    @MethodSource("allVersionsWithLifecycle")
    fun symmetricKey_canSaveLoadHex(version: Version, lifecycle: KeyLifecycle) {
        val key = SymmetricKey.generate(version)
        val saved = key.toHex()
        val loaded = SymmetricKey.ofHex(saved, version, lifecycle)

        loaded shouldBe key
        loaded.lifecycle shouldBe lifecycle
        loaded.clear()
    }

    @ParameterizedTest
    @MethodSource("allVersionsWithLifecycle")
    fun symmetricKey_canSaveLoadBase64Url(version: Version, lifecycle: KeyLifecycle) {
        val key = SymmetricKey.generate(version)
        val saved = key.toBase64Url()
        val loaded = SymmetricKey.ofBase64Url(saved, version, lifecycle)

        loaded shouldBe key
        loaded.lifecycle shouldBe lifecycle
        loaded.clear()
    }
}
