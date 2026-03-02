package net.aholbrook.paseto.crypto

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import net.aholbrook.paseto.exception.ByteArrayLengthException
import net.aholbrook.paseto.exception.KeyV3Exception
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.sec.ECPrivateKey
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.BigIntegers
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.math.BigInteger

private val secretKey = p384Generate().first
private val publicKey = p384SkToPk(secretKey)

class EcdsaTests {
    @ParameterizedTest
    @ValueSource(ints = [-1, 1])
    fun `ecdsaP384Sign rejects wrong sig length`(offset: Int) {
        shouldThrow<ByteArrayLengthException> {
            ecdsaP384Sign(ByteArray(ECDSA_P384_BYTES + offset), byteArrayOf(0x00), secretKey)
        }
    }

    @Test
    fun `ecdsaP384Sign rejects empty message`() {
        shouldThrow<ByteArrayLengthException> {
            ecdsaP384Sign(ByteArray(ECDSA_P384_BYTES), byteArrayOf(), secretKey)
        }
    }

    @ParameterizedTest
    @ValueSource(ints = [-1, 1])
    fun `ecdsaP384Sign rejects incorrect secret key size`(offset: Int) {
        shouldThrow<ByteArrayLengthException> {
            ecdsaP384Sign(
                ByteArray(ECDSA_P384_BYTES),
                "test".toByteArray(),
                ByteArray(ECDSA_P384_SECRETKEYBYTES + offset),
            )
        }
    }

    @Test
    fun `ecdsaP384Sign rejects 0 secret key`() {
        shouldThrow<KeyV3Exception> {
            val secretKey = BigIntegers.asUnsignedByteArray(ECDSA_P384_SECRETKEYBYTES, BigInteger.ZERO)
            ecdsaP384Sign(ByteArray(ECDSA_P384_BYTES), "test".toByteArray(), secretKey)
        }
    }

    @ParameterizedTest
    @ValueSource(longs = [0L, 1L])
    fun `ecdsaP384Sign checks secret key against n`(offset: Long) {
        shouldThrow<KeyV3Exception> {
            val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
            val secretKey = BigIntegers.asUnsignedByteArray(ECDSA_P384_SECRETKEYBYTES, curveParams.n.plus(BigInteger.valueOf(offset)))
            ecdsaP384Sign(ByteArray(ECDSA_P384_BYTES), "test".toByteArray(), secretKey)
        }
    }

    @Test
    fun `formatSignature correctly flips high-s to low-s`() {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val n = curveParams.n
        val halfN = n shr 1
        val r = BigInteger.ONE
        val highS = n.subtract(BigInteger.ONE)
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(sig, r, highS, n, enforceLowS = true)
        val result = BigInteger(1, sig.sliceArray(48 until 96))
        result shouldBe BigInteger.ONE
        (result <= halfN) shouldBe true
    }

    @Test
    fun `formatSignature ignores low-s when enforceLowS is true`() {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val n = curveParams.n
        val r = BigInteger.ONE
        val lowS = BigInteger.ONE
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(sig, r, lowS, n, enforceLowS = true)
        val result = BigInteger(1, sig.sliceArray(48 until 96))
        result shouldBe lowS
    }

    @Test
    fun `formatSignature correctly ignores high-s when enforceLowS is false`() {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val n = curveParams.n
        val r = BigInteger.ONE
        val highS = n.subtract(BigInteger.ONE)
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(sig, r, highS, n, enforceLowS = false)
        val result = BigInteger(1, sig.sliceArray(48 until 96))
        result shouldBe highS
    }

    @Test
    fun `formatSignature correctly ignores high-s by default`() {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val n = curveParams.n
        val r = BigInteger.ONE
        val highS = n.subtract(BigInteger.ONE)
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(sig, r, highS, n)
        val result = BigInteger(1, sig.sliceArray(48 until 96))
        result shouldBe highS
    }

    @ParameterizedTest
    @ValueSource(ints = [-1, 1])
    fun `ecdsaP384Verify rejects incorrect signature size`(offset: Int) {
        shouldThrow<ByteArrayLengthException> {
            ecdsaP384Verify(ByteArray(ECDSA_P384_BYTES + offset), "test".toByteArray(), publicKey)
        }
    }

    @Test
    fun `ecdsaP384Verify rejects empty message`() {
        shouldThrow<ByteArrayLengthException> {
            ecdsaP384Verify(ByteArray(ECDSA_P384_BYTES), byteArrayOf(), publicKey)
        }
    }

    @ParameterizedTest
    @ValueSource(ints = [-1, 1])
    fun `ecdsaP384Verify validates public key - size`(offset: Int) {
        shouldThrow<ByteArrayLengthException> {
            ecdsaP384Verify(
                sig = ByteArray(ECDSA_P384_BYTES),
                m = byteArrayOf(0x00),
                pk = ByteArray(ECDSA_P384_PUBLICKEYBYTES + offset),
            )
        }
    }

    @ParameterizedTest
    @ValueSource(bytes = [0x02, 0x03])
    fun `ecdsaP384Verify validates public key - allows compressed points`(firstByte: Byte) {
        shouldNotThrowAny {
            val pk = publicKey.copyOf()
            pk[0] = firstByte

            ecdsaP384Verify(
                sig = ByteArray(ECDSA_P384_BYTES),
                m = byteArrayOf(0x00),
                pk = pk,
            )
        }
    }

    @ParameterizedTest
    @ValueSource(bytes = [0x01, 0x04])
    fun `ecdsaP384Verify validates public key - rejects non-compressed points`(firstByte: Byte) {
        shouldThrow<KeyV3Exception> {
            val pk = publicKey.copyOf()
            pk[0] = firstByte

            ecdsaP384Verify(
                sig = ByteArray(ECDSA_P384_BYTES),
                m = byteArrayOf(0x00),
                pk = pk,
            )
        }
    }

    @Test
    fun `ecdsaP384Verify validates public key - handles exception during decode point`() {
        try {
            val mockParams = mockk<X9ECParameters>(relaxed = true)
            val mockCurve = mockk<ECCurve>()

            mockkStatic("org.bouncycastle.crypto.ec.CustomNamedCurves")
            every { CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1) } returns mockParams
            every { mockParams.curve } returns mockCurve
            every { mockCurve.decodePoint(any()) } throws IllegalArgumentException()

            shouldThrow<KeyV3Exception> {
                val pk = byteArrayOf(0x02) + BigInteger.ONE.toByteArray().copyOf(48)

                ecdsaP384Verify(
                    sig = ByteArray(ECDSA_P384_BYTES),
                    m = byteArrayOf(0x00),
                    pk = pk,
                )
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun `ecdsaP384Verify validates public key - checks q for infinity`() {
        try {
            val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
            val mockParams = mockk<X9ECParameters>(relaxed = true)
            val mockCurve = mockk<ECCurve>()

            mockkStatic("org.bouncycastle.crypto.ec.CustomNamedCurves")
            every { CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1) } returns mockParams
            every { mockParams.curve } returns mockCurve
            every { mockCurve.decodePoint(any()) } returns curveParams.curve.infinity

            shouldThrow<KeyV3Exception> {
                val pk = byteArrayOf(0x02) + BigInteger.ONE.toByteArray().copyOf(48)

                ecdsaP384Verify(
                    sig = ByteArray(ECDSA_P384_BYTES),
                    m = byteArrayOf(0x00),
                    pk = pk,
                )
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun `ecdsaP384Verify validates public key - checks q isValid`() {
        try {
            val mockParams = mockk<X9ECParameters>(relaxed = true)
            val mockCurve = mockk<ECCurve>()
            val mockQ = mockk<ECPoint>()

            mockkStatic("org.bouncycastle.crypto.ec.CustomNamedCurves")
            every { CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1) } returns mockParams
            every { mockParams.curve } returns mockCurve
            every { mockCurve.decodePoint(any()) } returns mockQ
            every { mockQ.isInfinity } returns false
            every { mockQ.isValid } returns false

            shouldThrow<KeyV3Exception> {
                val pk = byteArrayOf(0x02) + BigInteger.ONE.toByteArray().copyOf(48)

                ecdsaP384Verify(
                    sig = ByteArray(ECDSA_P384_BYTES),
                    m = byteArrayOf(0x00),
                    pk = pk,
                )
            }
        } finally {
            unmockkAll()
        }
    }

    @Test
    fun `ecdsaP384Verify rejects 0 r`() {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val r = BigInteger.ZERO
        val s = BigInteger.ONE
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(sig, r, s, curveParams.n, false)
        ecdsaP384Verify(sig, byteArrayOf(0x00), publicKey, false) shouldBe false
    }

    @ParameterizedTest
    @ValueSource(longs = [0L, 1L])
    fun `ecdsaP384Verify rejects large r`(offset: Long) {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val r = curveParams.n.plus(BigInteger.valueOf(offset))
        val s = BigInteger.ONE
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(sig, r, s, curveParams.n, false)
        ecdsaP384Verify(sig, byteArrayOf(0x00), publicKey, false) shouldBe false
    }

    @Test
    fun `ecdsaP384Verify rejects 0 s`() {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val r = BigInteger.ONE
        val s = BigInteger.ZERO
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(sig, r, s, curveParams.n, false)
        ecdsaP384Verify(sig, byteArrayOf(0x00), publicKey, false) shouldBe false
    }

    @ParameterizedTest
    @ValueSource(longs = [0L, 1L])
    fun `ecdsaP384Verify rejects large s`(offset: Long) {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val r = BigInteger.ONE
        val s = curveParams.n.plus(BigInteger.valueOf(offset))
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(sig, r, s, curveParams.n, false)
        ecdsaP384Verify(sig, byteArrayOf(0x00), publicKey, false) shouldBe false
    }

    @Test
    fun `ecdsaP384Verify correctly rejects high-s when enforceLowS is true`() {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val r = BigInteger.ONE
        val s = (curveParams.n shr 1).plus(BigInteger.ONE)
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(sig, r, s, curveParams.n, false)
        ecdsaP384Verify(sig, byteArrayOf(0x00), publicKey, true) shouldBe false
    }

    @Test
    fun `ecdsaP384Verify correctly accepts low-s when enforceLowS is true`() {
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaP384Sign(sig, "test".toByteArray(), secretKey, true) shouldBe true
        ecdsaP384Verify(sig, "test".toByteArray(), publicKey, true) shouldBe true
    }

    @Test
    fun `ecdsaP384Verify correctly accepts high-s when enforceLowS is false`() {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaP384Sign(sig, "test".toByteArray(), secretKey, true) shouldBe true
        val r = BigInteger(1, sig.copyOfRange(0, ECDSA_P384_BYTES / 2))
        var s = BigInteger(1, sig.copyOfRange(ECDSA_P384_BYTES / 2, sig.size))
        if (s <= curveParams.n shr 1) {
            s = curveParams.n.subtract(s)
        }
        val newSig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(newSig, r, s, curveParams.n, false)
        // be sure we have a high s value
        withClue("test failed to construct a high-s value") {
            ecdsaP384Verify(newSig, "test".toByteArray(), publicKey, true) shouldBe false
        }

        ecdsaP384Verify(newSig, "test".toByteArray(), publicKey, false) shouldBe true
    }

    @Test
    fun `ecdsaP384Verify correctly accepts high-s by default`() {
        val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val sig = ByteArray(ECDSA_P384_BYTES)
        ecdsaP384Sign(sig, "test".toByteArray(), secretKey, true) shouldBe true
        val r = BigInteger(1, sig.copyOfRange(0, ECDSA_P384_BYTES / 2))
        var s = BigInteger(1, sig.copyOfRange(ECDSA_P384_BYTES / 2, sig.size))
        if (s <= curveParams.n shr 1) {
            s = curveParams.n.subtract(s)
        }
        val newSig = ByteArray(ECDSA_P384_BYTES)
        ecdsaFormatSignature(newSig, r, s, curveParams.n, false)
        // be sure we have a high s value
        withClue("test failed to construct a high-s value") {
            ecdsaP384Verify(newSig, "test".toByteArray(), publicKey, true) shouldBe false
        }

        ecdsaP384Verify(newSig, "test".toByteArray(), publicKey, false) shouldBe true
    }

    @Test
    fun `p384SkToPk works correctly`() {
        val (sk, pk) = p384Generate()
        p384SkToPk(sk) shouldBe pk
    }

    @ParameterizedTest
    @ValueSource(ints = [-1, 1])
    fun `p384SkToPk rejects incorrect key sizes`(offset: Int) {
        shouldThrow<ByteArrayLengthException> {
            p384SkToPk(ByteArray(ECDSA_P384_SECRETKEYBYTES + offset))
        }
    }

    @Test
    fun `p384SkToPk rejects 0 d`() {
        val sk = BigIntegers.asUnsignedByteArray(ECDSA_P384_SECRETKEYBYTES, BigInteger.ZERO)

        shouldThrow<KeyV3Exception> {
            p384SkToPk(sk)
        }
    }

    @ParameterizedTest
    @ValueSource(longs = [0L, 1L])
    fun `p384SkToPk rejects high d`(offset: Long) {
        val params = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val sk = BigIntegers.asUnsignedByteArray(
            ECDSA_P384_SECRETKEYBYTES,
            params.n.plus(BigInteger.valueOf(offset)),
        )

        shouldThrow<KeyV3Exception> {
            p384SkToPk(sk)
        }
    }

    @Test
    fun `p384EncodeSkPkcs8 works correctly`() {
        val sk = byteArrayOf(
            10, 105, 47, -3, 40, 94, -72, -105, 116, -86, 106, -88, 55, 127, -12, -56, 82, -48, -91, -94, 12, -6, -121,
            89, 112, -51, 116, 10, 48, 55, 121, -100, 68, -82, 115, 4, 38, -92, -47, -61, -123, -38, 33, 83, -112, -61,
            85, -54,
        )

        val encoded = p384EncodeSkPkcs8(sk)
        encoded shouldBe byteArrayOf(
            48, 87, 2, 1, 0, 48, 16, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 5, 43, -127, 4, 0, 34, 4, 64, 48, 62, 2, 1,
            1, 4, 48, 10, 105, 47, -3, 40, 94, -72, -105, 116, -86, 106, -88, 55, 127, -12, -56, 82, -48, -91, -94, 12,
            -6, -121, 89, 112, -51, 116, 10, 48, 55, 121, -100, 68, -82, 115, 4, 38, -92, -47, -61, -123, -38, 33, 83,
            -112, -61, 85, -54, -96, 7, 6, 5, 43, -127, 4, 0, 34,
        )
    }

    @ParameterizedTest
    @ValueSource(ints = [-1, 1])
    fun `p384EncodeSkPkcs8 rejects incorrect key sizes`(offset: Int) {
        shouldThrow<ByteArrayLengthException> {
            p384EncodeSkPkcs8(ByteArray(ECDSA_P384_SECRETKEYBYTES + offset))
        }
    }

    @Test
    fun `p384EncodeSkPkcs8 rejects 0 d`() {
        val sk = BigIntegers.asUnsignedByteArray(ECDSA_P384_SECRETKEYBYTES, BigInteger.ZERO)

        shouldThrow<KeyV3Exception> {
            p384EncodeSkPkcs8(sk)
        }
    }

    @ParameterizedTest
    @ValueSource(longs = [0L, 1L])
    fun `p384EncodeSkPkcs8 rejects high d`(offset: Long) {
        val params = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val sk = BigIntegers.asUnsignedByteArray(
            ECDSA_P384_SECRETKEYBYTES,
            params.n.plus(BigInteger.valueOf(offset)),
        )

        shouldThrow<KeyV3Exception> {
            p384EncodeSkPkcs8(sk)
        }
    }

    @Test
    fun `p384DecodeSkPkcs8 works correctly`() {
        val encoded = byteArrayOf(
            48, 87, 2, 1, 0, 48, 16, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 5, 43, -127, 4, 0, 34, 4, 64, 48, 62, 2, 1,
            1, 4, 48, 10, 105, 47, -3, 40, 94, -72, -105, 116, -86, 106, -88, 55, 127, -12, -56, 82, -48, -91, -94, 12,
            -6, -121, 89, 112, -51, 116, 10, 48, 55, 121, -100, 68, -82, 115, 4, 38, -92, -47, -61, -123, -38, 33, 83,
            -112, -61, 85, -54, -96, 7, 6, 5, 43, -127, 4, 0, 34,
        )

        val sk = p384DecodeSkPkcs8(encoded)
        sk shouldBe byteArrayOf(
            10, 105, 47, -3, 40, 94, -72, -105, 116, -86, 106, -88, 55, 127, -12, -56, 82, -48, -91, -94, 12, -6, -121,
            89, 112, -51, 116, 10, 48, 55, 121, -100, 68, -82, 115, 4, 38, -92, -47, -61, -123, -38, 33, 83, -112, -61,
            85, -54,
        )
    }

    @Test
    fun `p384DecodeSkPkcs8 throws on empty array`() {
        shouldThrow<KeyV3Exception> {
            p384DecodeSkPkcs8(ByteArray(0))
        }
    }

    @Test
    fun `p384DecodeSkPkcs8 throws on incorrect key length`() {
        shouldThrow<KeyV3Exception> {
            p384DecodeSkPkcs8(ByteArray(3))
        }
    }

    @Test
    fun `p384DecodeSkPkcs8 throws on wrong key type`() {
        try {
            mockkStatic("org.bouncycastle.crypto.util.PrivateKeyFactory")
            every { PrivateKeyFactory.createKey(any<ByteArray>()) } returns mockk<Ed25519PrivateKeyParameters>()

            shouldThrow<KeyV3Exception> {
                p384DecodeSkPkcs8(ByteArray(89))
            }
        } finally {
            unmockkAll()
        }
    }

    @Nested
    inner class P384DecodeSkPkcs8Tests {
        val mockKeyParams = mockk<ECPrivateKeyParameters>()
        val mockDomainParams = mockk<ECDomainParameters>()

        @BeforeEach
        fun beforeEach() {
            mockkStatic("org.bouncycastle.crypto.util.PrivateKeyFactory")
            every { PrivateKeyFactory.createKey(any<ByteArray>()) } returns mockKeyParams
            every { mockKeyParams.parameters } returns mockDomainParams

            val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
            every { mockDomainParams.curve } returns curveParams.curve
            every { mockDomainParams.g } returns curveParams.g
            every { mockDomainParams.n } returns curveParams.n
            every { mockDomainParams.h } returns curveParams.h
        }

        @AfterEach
        fun afterEach() {
            unmockkAll()
        }

        @Test
        fun `wrong curve`() {
            every { mockDomainParams.curve } returns CustomNamedCurves.getByOID(SECObjectIdentifiers.secp521r1).curve
            shouldThrow<KeyV3Exception> {
                p384DecodeSkPkcs8(ByteArray(89))
            }
        }

        @Test
        fun `wrong g`() {
            every { mockDomainParams.g } returns CustomNamedCurves.getByOID(SECObjectIdentifiers.secp521r1).g
            shouldThrow<KeyV3Exception> {
                p384DecodeSkPkcs8(ByteArray(89))
            }
        }

        @Test
        fun `wrong n`() {
            every { mockDomainParams.n } returns BigInteger.ZERO
            shouldThrow<KeyV3Exception> {
                p384DecodeSkPkcs8(ByteArray(89))
            }
        }

        @Test
        fun `wrong h`() {
            every { mockDomainParams.h } returns BigInteger.ZERO
            shouldThrow<KeyV3Exception> {
                p384DecodeSkPkcs8(ByteArray(89))
            }
        }

        @Test
        fun `p384DecodeSkPkcs8 0 d`() {
            every { mockKeyParams.d } returns BigInteger.ZERO

            shouldThrow<KeyV3Exception> {
                p384DecodeSkPkcs8(ByteArray(0))
            }
        }

        @ParameterizedTest
        @ValueSource(longs = [0L, 1L])
        fun `p384DecodeSkPkcs8 high d`(offset: Long) {
            every { mockKeyParams.d } returns
                CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1).n.plus(BigInteger.valueOf(offset))

            shouldThrow<KeyV3Exception> {
                p384DecodeSkPkcs8(ByteArray(0))
            }
        }
    }

    @Test
    fun `p384EncodeSkSec1 works correctly`() {
        val sk = byteArrayOf(
            10, 105, 47, -3, 40, 94, -72, -105, 116, -86, 106, -88, 55, 127, -12, -56, 82, -48, -91, -94, 12, -6, -121,
            89, 112, -51, 116, 10, 48, 55, 121, -100, 68, -82, 115, 4, 38, -92, -47, -61, -123, -38, 33, 83, -112, -61,
            85, -54,
        )

        val encoded = p384EncodeSkSec1(sk)
        encoded shouldBe byteArrayOf(
            48, 62, 2, 1, 1, 4, 48, 10, 105, 47, -3, 40, 94, -72, -105, 116, -86, 106, -88, 55, 127, -12, -56, 82, -48,
            -91, -94, 12, -6, -121, 89, 112, -51, 116, 10, 48, 55, 121, -100, 68, -82, 115, 4, 38, -92, -47, -61, -123,
            -38, 33, 83, -112, -61, 85, -54, -96, 7, 6, 5, 43, -127, 4, 0, 34,
        )
    }

    @ParameterizedTest
    @ValueSource(ints = [-1, 1])
    fun `p384EncodeSkSec1 rejects incorrect key sizes`(offset: Int) {
        shouldThrow<ByteArrayLengthException> {
            p384EncodeSkSec1(ByteArray(ECDSA_P384_SECRETKEYBYTES + offset))
        }
    }

    @Test
    fun `p384EncodeSkSec1 rejects 0 d`() {
        val sk = BigIntegers.asUnsignedByteArray(ECDSA_P384_SECRETKEYBYTES, BigInteger.ZERO)

        shouldThrow<KeyV3Exception> {
            p384EncodeSkSec1(sk)
        }
    }

    @ParameterizedTest
    @ValueSource(longs = [0L, 1L])
    fun `p384EncodeSkSec1 rejects high d`(offset: Long) {
        val params = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
        val sk = BigIntegers.asUnsignedByteArray(
            ECDSA_P384_SECRETKEYBYTES,
            params.n.plus(BigInteger.valueOf(offset)),
        )

        shouldThrow<KeyV3Exception> {
            p384EncodeSkSec1(sk)
        }
    }

    @Test
    fun `p384DecodeSkSec1 works correctly`() {
        val encoded = byteArrayOf(
            48, 62, 2, 1, 1, 4, 48, 10, 105, 47, -3, 40, 94, -72, -105, 116, -86, 106, -88, 55, 127, -12, -56, 82, -48,
            -91, -94, 12, -6, -121, 89, 112, -51, 116, 10, 48, 55, 121, -100, 68, -82, 115, 4, 38, -92, -47, -61, -123,
            -38, 33, 83, -112, -61, 85, -54, -96, 7, 6, 5, 43, -127, 4, 0, 34,
        )

        val sk = p384DecodeSkSec1(encoded)
        sk shouldBe byteArrayOf(
            10, 105, 47, -3, 40, 94, -72, -105, 116, -86, 106, -88, 55, 127, -12, -56, 82, -48, -91, -94, 12, -6, -121,
            89, 112, -51, 116, 10, 48, 55, 121, -100, 68, -82, 115, 4, 38, -92, -47, -61, -123, -38, 33, 83, -112, -61,
            85, -54,
        )
    }

    @Test
    fun `p384DecodeSkSec1 throws on empty array`() {
        shouldThrow<KeyV3Exception> {
            p384DecodeSkSec1(ByteArray(0))
        }
    }

    @Test
    fun `p384DecodeSkSec1 throws on incorrect key length`() {
        shouldThrow<KeyV3Exception> {
            p384DecodeSkSec1(ByteArray(3))
        }
    }

    @Nested
    inner class P384DecodeSkSec1Tests {
        val mockKey = mockk<ECPrivateKey>()

        @BeforeEach
        fun beforeEach() {
            mockkStatic("org.bouncycastle.asn1.ASN1Primitive")
            mockkStatic("org.bouncycastle.asn1.sec.ECPrivateKey")
            every { ASN1Primitive.fromByteArray(any()) } returns mockk(relaxed = true)
            every { ECPrivateKey.getInstance(any()) } returns mockKey
        }

        @AfterEach
        fun afterEach() {
            unmockkAll()
        }

        @Test
        fun `throws when given wrong curve`() {
            every { mockKey.parametersObject } returns SECObjectIdentifiers.secp521r1
            shouldThrow<KeyV3Exception> {
                p384DecodeSkSec1(ByteArray(89))
            }
        }

        @Test
        fun `throws when given unsupported curve parameters`() {
            every { mockKey.parametersObject } returns mockk()
            shouldThrow<KeyV3Exception> {
                p384DecodeSkSec1(ByteArray(89))
            }
        }

        @Test
        fun `throws when key has no curve information`() {
            every { mockKey.parametersObject } returns null
            shouldThrow<KeyV3Exception> {
                p384DecodeSkSec1(ByteArray(89))
            }
        }

        @Test
        fun `throws when d is 0`() {
            every { mockKey.parametersObject } returns SECObjectIdentifiers.secp384r1
            every { mockKey.key } returns BigInteger.ZERO

            shouldThrow<KeyV3Exception> {
                p384DecodeSkSec1(ByteArray(89))
            }
        }

        @ParameterizedTest
        @ValueSource(longs = [0L, 1L])
        fun `throws when d is large`(offset: Long) {
            val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)

            every { mockKey.parametersObject } returns SECObjectIdentifiers.secp384r1
            every { mockKey.key } returns curveParams.n.plus(BigInteger.valueOf(offset))

            shouldThrow<KeyV3Exception> {
                p384DecodeSkSec1(ByteArray(89))
            }
        }
    }

    @Test
    fun `p384EncodePkSpki works correctly`() {
        val pk = byteArrayOf(
            3, -46, 91, 61, -87, 49, -70, 0, -50, 92, -48, 21, 98, 64, -113, -5, -17, 46, -6, -83, 20, 95, -26, -2,
            -119, 84, 1, -14, -13, -64, 11, -3, 71, 110, 102, 102, 53, 100, -15, 105, 61, -87, 8, -70, -122, 86, -116,
            -4, -125,
        )

        val encoded = p384EncodePkSpki(pk)
        encoded shouldBe byteArrayOf(
            48, 70, 48, 16, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 5, 43, -127, 4, 0, 34, 3, 50, 0, 3, -46, 91, 61, -87,
            49, -70, 0, -50, 92, -48, 21, 98, 64, -113, -5, -17, 46, -6, -83, 20, 95, -26, -2, -119, 84, 1, -14, -13,
            -64, 11, -3, 71, 110, 102, 102, 53, 100, -15, 105, 61, -87, 8, -70, -122, 86, -116, -4, -125,
        )
    }

    @Test
    fun `p384DecodePkSpki works correctly`() {
        val encoded = byteArrayOf(
            48, 70, 48, 16, 6, 7, 42, -122, 72, -50, 61, 2, 1, 6, 5, 43, -127, 4, 0, 34, 3, 50, 0, 3, -46, 91, 61, -87,
            49, -70, 0, -50, 92, -48, 21, 98, 64, -113, -5, -17, 46, -6, -83, 20, 95, -26, -2, -119, 84, 1, -14, -13,
            -64, 11, -3, 71, 110, 102, 102, 53, 100, -15, 105, 61, -87, 8, -70, -122, 86, -116, -4, -125,
        )

        val pk = p384DecodePkSpki(encoded)
        pk shouldBe byteArrayOf(
            3, -46, 91, 61, -87, 49, -70, 0, -50, 92, -48, 21, 98, 64, -113, -5, -17, 46, -6, -83, 20, 95, -26, -2,
            -119, 84, 1, -14, -13, -64, 11, -3, 71, 110, 102, 102, 53, 100, -15, 105, 61, -87, 8, -70, -122, 86, -116,
            -4, -125,
        )
    }

    @Test
    fun `p384DecodePkSpki throws on empty array`() {
        shouldThrow<KeyV3Exception> {
            p384DecodePkSpki(ByteArray(0))
        }
    }

    @Test
    fun `p384DecodePkSpki throws on incorrect key length`() {
        shouldThrow<KeyV3Exception> {
            p384DecodePkSpki(ByteArray(3))
        }
    }

    @Test
    fun `p384DecodePkSpki throws on wrong key type`() {
        try {
            mockkStatic("org.bouncycastle.crypto.util.PublicKeyFactory")
            every { PublicKeyFactory.createKey(any<ByteArray>()) } returns null

            shouldThrow<KeyV3Exception> {
                p384DecodePkSpki(ByteArray(89))
            }
        } finally {
            unmockkAll()
        }
    }

    @Nested
    inner class P384DecodePkSpkiTests {
        val mockKeyParams = mockk<ECPublicKeyParameters>()
        val mockDomainParams = mockk<ECDomainParameters>()

        @BeforeEach
        fun beforeEach() {
            mockkStatic("org.bouncycastle.crypto.util.PublicKeyFactory")
            every { PublicKeyFactory.createKey(any<ByteArray>()) } returns mockKeyParams
            every { mockKeyParams.parameters } returns mockDomainParams

            val curveParams = CustomNamedCurves.getByOID(SECObjectIdentifiers.secp384r1)
            every { mockDomainParams.curve } returns curveParams.curve
            every { mockDomainParams.g } returns curveParams.g
            every { mockDomainParams.n } returns curveParams.n
            every { mockDomainParams.h } returns curveParams.h
        }

        @AfterEach
        fun afterEach() {
            unmockkAll()
        }

        @Test
        fun `wrong curve`() {
            every { mockDomainParams.curve } returns CustomNamedCurves.getByOID(SECObjectIdentifiers.secp521r1).curve
            shouldThrow<KeyV3Exception> {
                p384DecodePkSpki(ByteArray(89))
            }
        }

        @Test
        fun `wrong g`() {
            every { mockDomainParams.g } returns CustomNamedCurves.getByOID(SECObjectIdentifiers.secp521r1).g
            shouldThrow<KeyV3Exception> {
                p384DecodePkSpki(ByteArray(89))
            }
        }

        @Test
        fun `wrong n`() {
            every { mockDomainParams.n } returns BigInteger.ZERO
            shouldThrow<KeyV3Exception> {
                p384DecodePkSpki(ByteArray(89))
            }
        }

        @Test
        fun `wrong h`() {
            every { mockDomainParams.h } returns BigInteger.ZERO
            shouldThrow<KeyV3Exception> {
                p384DecodePkSpki(ByteArray(89))
            }
        }
    }
}
