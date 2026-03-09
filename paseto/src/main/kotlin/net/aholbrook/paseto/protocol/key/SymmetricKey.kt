package net.aholbrook.paseto.protocol.key

import net.aholbrook.paseto.crypto.randomBytes
import net.aholbrook.paseto.exception.KeyClearedException
import net.aholbrook.paseto.exception.KeyLengthException
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.Version
import org.bouncycastle.util.encoders.Hex
import kotlin.io.encoding.Base64

/**
 * Symmetric key used for `v*.local` encryption/decryption.
 *
 * @property version PASETO [Version] this key is bound to.
 * @property lifecycle [KeyLifecycle] behavior for key material retention.
 */
class SymmetricKey private constructor(
    private val material: ByteArray,
    val version: Version,
    val lifecycle: KeyLifecycle,
) {
    internal val purpose: Purpose = Purpose.LOCAL
    private var cleared: Boolean = false

    init {
        if (version.symmetricKeySize != material.size) {
            throw KeyLengthException(material.size, arrayOf(version.symmetricKeySize))
        }
    }

    /**
     * Copy this key into a new instance.
     *
     * The default copy is [KeyLifecycle.EPHEMERAL] to reduce accidental long-lived key reuse.
     *
     * @param lifecycle Lifecycle to assign to the copied key.
     * @return Copied [SymmetricKey].
     */
    fun copy(lifecycle: KeyLifecycle = KeyLifecycle.EPHEMERAL): SymmetricKey =
        SymmetricKey(material.copyOf(), version, lifecycle)

    fun toHex(): String {
        if (cleared) throw KeyClearedException()
        return Hex.toHexString(material)
    }

    fun toBase64Url(): String {
        if (cleared) throw KeyClearedException()
        return Base64.UrlSafe.encode(material)
    }

    internal fun getKeyMaterialFor(version: Version, purpose: Purpose): ByteArray {
        if (cleared) throw KeyClearedException()
        if (this.version != version) throw KeyVersionException(version, this.version)
        if (this.purpose != purpose) throw KeyPurposeException(purpose.toString(), this.purpose.toString())
        return material
    }

    internal fun clear() {
        material.fill(0)
        cleared = true
    }

    internal fun internalClear() {
        if (lifecycle == KeyLifecycle.EPHEMERAL) clear()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (javaClass != other?.javaClass) {
            return false
        }

        other as SymmetricKey

        if (version != other.version) {
            return false
        }
        if (purpose != other.purpose) {
            return false
        }
        if (!material.contentEquals(other.material)) {
            return false
        }

        return true
    }

    override fun hashCode(): Int {
        var result = material.contentHashCode()
        result = 31 * result + version.hashCode()
        result = 31 * result + purpose.hashCode()
        return result
    }

    override fun toString(): String = "SymmetricKey(material=*****, version=$version, purpose=$purpose)"

    companion object {
        /**
         * Generate a symmetric key for the given [version].
         *
         * @param version PASETO [Version].
         * @param lifecycle [KeyLifecycle] policy for returned key.
         * @return Generated [SymmetricKey].
         */
        @JvmStatic
        fun generate(version: Version, lifecycle: KeyLifecycle = KeyLifecycle.PERSISTENT) =
            ofRawBytes(randomBytes(version.symmetricKeySize), version, lifecycle)

        /**
         * Create a key from raw bytes.
         *
         * @param material Raw key bytes.
         * @param version PASETO [Version].
         * @param lifecycle [KeyLifecycle] policy for returned key.
         * @return [SymmetricKey] instance.
         */
        @JvmStatic
        fun ofRawBytes(material: ByteArray, version: Version, lifecycle: KeyLifecycle = KeyLifecycle.PERSISTENT) =
            SymmetricKey(material, version, lifecycle)

        /**
         * Create a key from a hex-encoded string.
         *
         * @param hex Hex-encoded key bytes.
         * @param version PASETO [Version].
         * @param lifecycle [KeyLifecycle] policy for returned key.
         * @return [SymmetricKey] instance.
         */
        @JvmStatic
        fun ofHex(hex: String, version: Version, lifecycle: KeyLifecycle = KeyLifecycle.PERSISTENT) =
            SymmetricKey(Hex.decode(hex), version, lifecycle)

        /**
         * Create a key from URL-safe base64 text.
         *
         * @param b64 Base64url-encoded key bytes.
         * @param version PASETO [Version].
         * @param lifecycle [KeyLifecycle] policy for returned key.
         * @return [SymmetricKey] instance.
         */
        @JvmStatic
        fun ofBase64Url(b64: String, version: Version, lifecycle: KeyLifecycle = KeyLifecycle.PERSISTENT) =
            SymmetricKey(Base64.UrlSafe.decode(b64), version, lifecycle)
    }
}
