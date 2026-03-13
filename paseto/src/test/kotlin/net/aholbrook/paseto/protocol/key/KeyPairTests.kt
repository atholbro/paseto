package net.aholbrook.paseto.protocol.key

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.mockk.every
import io.mockk.mockk
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.keyV2Public
import net.aholbrook.paseto.keyV4Public
import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.Version
import org.junit.jupiter.api.Test

class KeyPairTests {
    @Test
    fun `KeyPair equals and hashCode`() {
        val keyPair = keyV4Public

        keyPair shouldBe keyPair
        keyPair shouldNotBe null
        keyPair.hashCode() shouldBe keyPair.hashCode()
        keyPair shouldNotBe ""
        keyPair shouldBe keyPair.copy()
        keyPair.hashCode() shouldBe keyPair.copy().hashCode()

        // different version
        keyPair shouldNotBe keyV2Public
        keyPair.hashCode() shouldNotBe keyV2Public.hashCode()

        // different secret key
        val differentSecret = KeyPair(
            AsymmetricSecretKey.ofHex("1".repeat(64), Version.V4),
            keyPair.publicKey,
        )
        keyPair shouldNotBe differentSecret
        keyPair.hashCode() shouldNotBe differentSecret.hashCode()

        // different public key
        val differentPublic = KeyPair(
            keyPair.secretKey,
            AsymmetricPublicKey.ofHex("1".repeat(64), Version.V4),
        )
        keyPair shouldNotBe differentPublic
        keyPair.hashCode() shouldNotBe differentPublic.hashCode()

        // null secret key
        val publicOnly = KeyPair(null, keyPair.publicKey)
        keyPair shouldNotBe publicOnly
        publicOnly shouldBe KeyPair(null, keyPair.publicKey)
        publicOnly.hashCode() shouldBe KeyPair(null, keyPair.publicKey).hashCode()
    }

    @Test
    fun `keyPair enforces version match`() {
        shouldThrow<KeyVersionException> {
            KeyPair(keyV4Public.secretKey, keyV2Public.publicKey)
        }
    }

    @Test
    fun `keyPair checks for public purpose on secretKey`() {
        val secretKey = mockk<AsymmetricSecretKey>()
        val publicKey = keyV4Public.publicKey
        every { secretKey.purpose } returns Purpose.LOCAL
        every { secretKey.version } returns publicKey.version

        shouldThrow<KeyPurposeException> {
            KeyPair(secretKey, publicKey)
        }
    }

    @Test
    fun `keyPair checks for public purpose on publicKey`() {
        val secretKey = keyV2Public.secretKey!!
        val publicKey = mockk<AsymmetricPublicKey>()
        every { publicKey.purpose } returns Purpose.LOCAL
        every { publicKey.version } returns secretKey.version

        shouldThrow<KeyPurposeException> {
            KeyPair(secretKey, publicKey)
        }
    }
}
