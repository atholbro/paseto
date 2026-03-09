package net.aholbrook.paseto.protocol.key

import net.aholbrook.paseto.crypto.ed25519Generate
import net.aholbrook.paseto.crypto.p384Generate
import net.aholbrook.paseto.crypto.rsaGenerate
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.exception.Pkcs12LoadException
import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.Version
import java.io.IOException
import java.io.InputStream
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException

/**
 * Public-token key pair.
 *
 * [secretKey] may be `null` for verify-only services.
 *
 * @property secretKey Secret key used for signing (nullable for verify-only usage).
 * @property publicKey Public key used for verification.
 */
class KeyPair(val secretKey: AsymmetricSecretKey?, val publicKey: AsymmetricPublicKey) {
    init {
        if (secretKey != null && secretKey.version != publicKey.version) {
            throw KeyVersionException(secretKey.version, publicKey.version)
        }
        if (secretKey != null && secretKey.purpose != Purpose.PUBLIC) {
            throw KeyPurposeException(Purpose.PUBLIC.toString(), secretKey.purpose.toString())
        }
        if (publicKey.purpose != Purpose.PUBLIC) {
            throw KeyPurposeException(Purpose.PUBLIC.toString(), publicKey.purpose.toString())
        }
    }

    val version: Version = publicKey.version

    /**
     * Copy this key into a new instance.
     *
     * The default copy is [KeyLifecycle.EPHEMERAL] to reduce accidental long-lived key reuse.
     *
     * @param lifecycle Lifecycle to assign to the copied key.
     * @return Copied [KeyPair].
     */
    fun copy(lifecycle: KeyLifecycle = KeyLifecycle.EPHEMERAL): KeyPair = KeyPair(secretKey?.copy(lifecycle), publicKey)

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (javaClass != other?.javaClass) {
            return false
        }

        other as KeyPair

        if (version != other.version) {
            return false
        }
        if (secretKey != other.secretKey) {
            return false
        }
        if (publicKey != other.publicKey) {
            return false
        }

        return true
    }

    override fun hashCode(): Int {
        var result = secretKey?.hashCode() ?: 0
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + version.hashCode()
        return result
    }

    companion object {
        /**
         * Generate a new key pair for the given [version].
         *
         * @param version PASETO [Version].
         * @param lifecycle [KeyLifecycle] policy for generated secret key.
         * @return Generated [KeyPair].
         */
        @JvmStatic
        fun generate(version: Version, lifecycle: KeyLifecycle = KeyLifecycle.PERSISTENT): KeyPair {
            val (secretKey, publicKey) = when (version) {
                Version.V1 -> rsaGenerate()
                Version.V2 -> ed25519Generate()
                Version.V3 -> p384Generate()
                Version.V4 -> ed25519Generate()
            }

            return KeyPair(
                secretKey = AsymmetricSecretKey.ofRawBytes(secretKey, version, lifecycle),
                publicKey = AsymmetricPublicKey.ofRawBytes(publicKey, version),
            )
        }

        /**
         * Load an RSA key pair from a PKCS#12 keystore stream.
         *
         * This helper is intended for `v1.public` key material.
         *
         * @param input Stream providing the `.p12`/`.pfx` keystore data.
         * @param keystorePass Keystore password.
         * @param alias Alias containing key/certificate entries.
         * @param keyPass Private key password (defaults to [keystorePass]).
         * @return Loaded [KeyPair].
         */
        @JvmStatic
        @JvmOverloads
        fun ofPkcs12(
            input: InputStream,
            keystorePass: String,
            alias: String,
            keyPass: String = keystorePass,
        ): KeyPair {
            try {
                val p12 = KeyStore.getInstance("PKCS12")
                p12.load(input, keystorePass.toCharArray())

                val privateKey = p12.getKey(alias, keyPass.toCharArray()) as? PrivateKey
                    ?: throw Pkcs12LoadException(Pkcs12LoadException.Reason.PRIVATE_KEY_NOT_FOUND)
                val cert = p12.getCertificate(alias)
                    ?: throw Pkcs12LoadException(Pkcs12LoadException.Reason.PUBLIC_KEY_NOT_FOUND)
                val publicKey = cert.publicKey

                return KeyPair(
                    AsymmetricSecretKey.ofRawBytes(privateKey.encoded, Version.V1),
                    AsymmetricPublicKey.ofRawBytes(publicKey.encoded, Version.V1),
                )
            } catch (e: CertificateException) {
                throw Pkcs12LoadException(e) // Unlikely to ever throw.
            } catch (e: NoSuchAlgorithmException) {
                throw Pkcs12LoadException(e) // Unlikely to occur on any modern jvm.
            } catch (e: UnrecoverableKeyException) {
                throw Pkcs12LoadException(e)
            } catch (e: IOException) {
                throw Pkcs12LoadException(e)
            } catch (e: KeyStoreException) {
                // This can only occur if you forget to call load, thus this will never throw.
                throw IllegalStateException(e)
            }
        }
    }
}
