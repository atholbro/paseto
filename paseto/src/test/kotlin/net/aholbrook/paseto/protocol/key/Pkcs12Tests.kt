package net.aholbrook.paseto.protocol.key

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import net.aholbrook.paseto.TestFiles
import net.aholbrook.paseto.exception.Pkcs12LoadException
import net.aholbrook.paseto.protocol.Version
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import java.util.stream.Stream

class Pkcs12Tests {
    @Test
    fun pkcs12Load_withDefaultKeyPassword() {
        val keys = KeyPair.ofPkcs12(
            keystoreFile = TestFiles.p12ResourcePath("rfc_v1_rsa.p12"),
            keystorePass = "testtest",
            alias = "test",
        )

        keys.secretKey!!.version shouldBe Version.V1
        keys.publicKey.version shouldBe Version.V1
    }

    @Test
    fun pkcs12Load_withExplicitKeyPassword() {
        val keys = KeyPair.ofPkcs12(
            keystoreFile = TestFiles.p12ResourcePath("test_v1_rsa.p12"),
            keystorePass = "password",
            alias = "test",
            keyPass = "password",
        )

        keys.secretKey!!.version shouldBe Version.V1
        keys.publicKey.version shouldBe Version.V1
    }

    @Test
    fun pkcs12Load_notFound() {
        val missingFile = File.createTempFile("missing-p12", ".p12").apply { delete() }

        val ex = shouldThrow<Pkcs12LoadException> {
            KeyPair.ofPkcs12(
                keystoreFile = missingFile.path,
                keystorePass = "testtest",
                alias = "test",
                keyPass = "testtest",
            )
        }

        ex.reason shouldBe Pkcs12LoadException.Reason.FILE_NOT_FOUND
    }

    @Test
    fun pkcs12Load_wrongPassword() {
        val ex = shouldThrow<Pkcs12LoadException> {
            KeyPair.ofPkcs12(
                keystoreFile = TestFiles.p12ResourcePath("rfc_v1_rsa.p12"),
                keystorePass = "wrong",
                alias = "test",
                keyPass = "testtest",
            )
        }

        ex.reason shouldBe Pkcs12LoadException.Reason.INCORRECT_PASSWORD
    }

    @Test
    fun pkcs12Load_wrongAlias() {
        val ex = shouldThrow<Pkcs12LoadException> {
            KeyPair.ofPkcs12(
                keystoreFile = TestFiles.p12ResourcePath("rfc_v1_rsa.p12"),
                keystorePass = "testtest",
                alias = "wrong",
                keyPass = "testtest",
            )
        }

        ex.reason shouldBe Pkcs12LoadException.Reason.PRIVATE_KEY_NOT_FOUND
    }

    @Test
    fun pkcs12Load_wrongKeyPassword() {
        val ex = shouldThrow<Pkcs12LoadException> {
            KeyPair.ofPkcs12(
                keystoreFile = TestFiles.p12ResourcePath("rfc_v1_rsa.p12"),
                keystorePass = "testtest",
                alias = "test",
                keyPass = "wrong",
            )
        }

        ex.reason shouldBe Pkcs12LoadException.Reason.UNRECOVERABLE_KEY
    }

    @Test
    fun pkcs12Load_noCertificate() {
        val ex = shouldThrow<Pkcs12LoadException> {
            KeyPair.ofPkcs12(
                keystoreFile = TestFiles.p12ResourcePath("test_v1_rsa_nopub.p12"),
                keystorePass = "password",
                alias = "test",
                keyPass = "password",
            )
        }

        ex.reason shouldBe Pkcs12LoadException.Reason.PUBLIC_KEY_NOT_FOUND
    }

    @Test
    fun pkcs12Load_corruptFile() {
        val ex = shouldThrow<Pkcs12LoadException> {
            KeyPair.ofPkcs12(
                keystoreFile = TestFiles.p12ResourcePath("test_v1_rsa_corrupt.p12"),
                keystorePass = "password",
                alias = "test",
                keyPass = "password",
            )
        }

        ex.reason shouldBe Pkcs12LoadException.Reason.IO_EXCEPTION
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("reasonMappings")
    fun pkcs12LoadException_reasonMappings(
        name: String,
        cause: Throwable,
        expected: Pkcs12LoadException.Reason,
    ) {
        val actual = when (cause) {
            is FileNotFoundException -> Pkcs12LoadException(cause)
            is NoSuchAlgorithmException -> Pkcs12LoadException(cause)
            is UnrecoverableKeyException -> Pkcs12LoadException(cause)
            is CertificateException -> Pkcs12LoadException(cause)
            is IOException -> Pkcs12LoadException(cause)
            else -> error("Unsupported throwable type for mapping test: ${cause::class.java.name}")
        }

        actual.reason shouldBe expected
    }

    @Nested
    inner class Pkcs12LoadRareExceptions {
        @BeforeEach
        fun beforeEach() {
            mockkStatic(KeyStore::class)
        }

        @AfterEach
        fun afterEach() {
            unmockkAll()
        }

        @Test
        fun pkcs12Load_KeyStoreException() {
            every { KeyStore.getInstance(any()) } throws KeyStoreException()

            val ex = shouldThrow<RuntimeException> {
                KeyPair.ofPkcs12("", "", "", "")
            }
            withClue("check type KeyStoreException") {
                (ex.cause is KeyStoreException) shouldBe true
            }
        }

        @Test
        fun pkcs12Load_CertificateException() {
            val mockKeyStore = mockk<KeyStore>()
            every { KeyStore.getInstance(any()) } returns mockKeyStore
            every { mockKeyStore.load(any(), any()) } throws CertificateException()

            val ex = shouldThrow<Pkcs12LoadException> {
                KeyPair.ofPkcs12(
                    keystoreFile = TestFiles.p12ResourcePath("rfc_v1_rsa.p12"),
                    keystorePass = "testtest",
                    alias = "test",
                )
            }
            withClue("check type CertificateException") {
                (ex.cause is CertificateException) shouldBe true
            }
        }

        @Test
        fun pkcs12Load_NoSuchAlgorithmException() {
            val mockKeyStore = mockk<KeyStore>()
            every { KeyStore.getInstance(any()) } returns mockKeyStore
            every { mockKeyStore.load(any(), any()) } throws NoSuchAlgorithmException()

            val ex = shouldThrow<Pkcs12LoadException> {
                KeyPair.ofPkcs12(
                    keystoreFile = TestFiles.p12ResourcePath("rfc_v1_rsa.p12"),
                    keystorePass = "testtest",
                    alias = "test",
                )
            }
            withClue("check type NoSuchAlgorithmException") {
                (ex.cause is NoSuchAlgorithmException) shouldBe true
            }
        }
    }

    companion object {
        @JvmStatic
        fun reasonMappings(): Stream<Arguments> = Stream.of(
            Arguments.of(
                "FileNotFoundException -> FILE_NOT_FOUND",
                FileNotFoundException(),
                Pkcs12LoadException.Reason.FILE_NOT_FOUND,
            ),
            Arguments.of(
                "NoSuchAlgorithmException -> ALGORITHM_NOT_FOUND",
                NoSuchAlgorithmException(),
                Pkcs12LoadException.Reason.ALGORITHM_NOT_FOUND,
            ),
            Arguments.of(
                "UnrecoverableKeyException -> UNRECOVERABLE_KEY",
                UnrecoverableKeyException(),
                Pkcs12LoadException.Reason.UNRECOVERABLE_KEY,
            ),
            Arguments.of(
                "CertificateException -> CERTIFICATE_ERROR",
                CertificateException(),
                Pkcs12LoadException.Reason.CERTIFICATE_ERROR,
            ),
            Arguments.of(
                "IOException -> IO_EXCEPTION",
                IOException(),
                Pkcs12LoadException.Reason.IO_EXCEPTION,
            ),
            Arguments.of(
                "IOException(UnrecoverableKeyException) -> INCORRECT_PASSWORD",
                IOException(UnrecoverableKeyException()),
                Pkcs12LoadException.Reason.INCORRECT_PASSWORD,
            ),
        )
    }
}
