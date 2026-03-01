package net.aholbrook.paseto.protocol

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import net.aholbrook.paseto.TestFiles
import net.aholbrook.paseto.crypto.copy
import net.aholbrook.paseto.exception.KeyLengthException
import net.aholbrook.paseto.exception.KeyPemUnsupportedTypeException
import net.aholbrook.paseto.exception.KeyPurposeException
import net.aholbrook.paseto.exception.KeyVersionException
import net.aholbrook.paseto.exception.Pkcs12LoadException
import net.aholbrook.paseto.keyV1Public
import net.aholbrook.paseto.keyV2Public
import net.aholbrook.paseto.keyV4Local
import net.aholbrook.paseto.keyV4Public
import net.aholbrook.paseto.protocol.KeyPair.Companion.pkcs12Load
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
import kotlin.io.encoding.Base64

class KeyTests {
    companion object {
        @JvmStatic
        fun keyPairsAllVersions(): Stream<Arguments> = listOf(keyV1Public, keyV2Public, keyV4Public).map { Arguments.of(it) }.stream()

        @JvmStatic
        fun allVersions(): Stream<Arguments> = listOf(Version.V1, Version.V2, Version.V4).map { Arguments.of(it) }.stream()
    }

    @ParameterizedTest
    @MethodSource("keyPairsAllVersions")
    fun `AsymmetricPublicKey can be recovered from AsymmetricSecretKey`(keyPair: KeyPair) {
        AsymmetricPublicKey.fromSecretKey(keyPair.secretKey!!) shouldBe keyPair.publicKey
    }

    @Test
    fun `AsymmetricPublicKey enforces key lengths`() {
        shouldThrow<KeyLengthException> {
            AsymmetricPublicKey.ofHex("0".repeat(10), Version.V4)
        }
    }

    @Test
    fun `AsymmetricSecretKey enforces key lengths`() {
        shouldThrow<KeyLengthException> {
            AsymmetricSecretKey.ofHex("0".repeat(10), Version.V4)
        }
    }

    @Test
    fun `SymmetricKey enforces key lengths`() {
        shouldThrow<KeyLengthException> {
            SymmetricKey.ofHex("0".repeat(10), Version.V4)
        }
    }

    @Test
    fun `AsymmetricPublicKey enforces version match on getKeyMaterialFor`() {
        shouldThrow<KeyVersionException> {
            keyV4Public.publicKey.getKeyMaterialFor(Version.V2, Purpose.PUBLIC)
        }
    }

    @Test
    fun `AsymmetricPublicKey enforces purpose match on getKeyMaterialFor`() {
        shouldThrow<KeyPurposeException> {
            keyV4Public.publicKey.getKeyMaterialFor(Version.V4, Purpose.LOCAL)
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

    @Test
    fun asymmetricPublicKey_ofBase64Url() {
        val b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val key = AsymmetricPublicKey.ofBase64Url(b64, Version.V4)
        key.getKeyMaterialFor(Version.V4, Purpose.PUBLIC) contentEquals Base64.UrlSafe.decode(b64)
    }

    @Test
    fun asymmetricSecretKey_ofBase64Url() {
        val b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val key = AsymmetricSecretKey.ofBase64Url(b64, Version.V4)
        key.getKeyMaterialFor(Version.V4, Purpose.PUBLIC) contentEquals Base64.UrlSafe.decode(b64)
    }

    @Test
    fun symmetricKey_ofBase64Url() {
        val b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val key = SymmetricKey.ofBase64Url(b64, Version.V4)
        key.getKeyMaterialFor(Version.V4, Purpose.LOCAL) contentEquals Base64.UrlSafe.decode(b64)
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

class Pkcs12Tests {
    @Test
    fun pkcs12Load_withDefaultKeyPassword() {
        val keys = pkcs12Load(
            keystoreFile = TestFiles.p12ResourcePath("rfc_v1_rsa.p12"),
            keystorePass = "testtest",
            alias = "test",
        )

        keys.secretKey!!.version shouldBe Version.V1
        keys.publicKey.version shouldBe Version.V1
    }

    @Test
    fun pkcs12Load_withExplicitKeyPassword() {
        val keys = pkcs12Load(
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
            pkcs12Load(
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
            pkcs12Load(
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
            pkcs12Load(
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
            pkcs12Load(
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
            pkcs12Load(
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
            pkcs12Load(
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
                pkcs12Load("", "", "", "")
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
                pkcs12Load(
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
                pkcs12Load(
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
