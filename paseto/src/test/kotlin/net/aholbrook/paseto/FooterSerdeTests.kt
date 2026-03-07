package net.aholbrook.paseto

import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.serialization.json.Json
import net.aholbrook.paseto.exception.FooterExceedsMaxDepthException
import net.aholbrook.paseto.exception.FooterExceedsMaxKeysException
import net.aholbrook.paseto.exception.FooterExceedsMaxLengthException
import net.aholbrook.paseto.exception.FooterJsonParseException
import net.aholbrook.paseto.exception.IncorrectFooterException
import net.aholbrook.paseto.exception.PasetoParseException
import net.aholbrook.paseto.protocol.Version
import net.aholbrook.paseto.rules.IssuedInPast
import net.aholbrook.paseto.rules.NotExpired
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.MethodSource
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.stream.Stream
import kotlin.io.encoding.Base64

enum class FooterApi {
    DECODE,
    INSECURE_GET_FOOTER,
}

class FooterSerdeTests {
    companion object {
        @JvmStatic
        fun allServiceConfigurations(): Stream<Arguments> = listOf(
            Pair(Version.V1, Purpose.Local { keyV1Local }),
            Pair(Version.V1, Purpose.Public { keyV1Public }),
            Pair(Version.V2, Purpose.Local { keyV2Local }),
            Pair(Version.V2, Purpose.Public { keyV2Public }),
            Pair(Version.V4, Purpose.Local { keyV4Local }),
            Pair(Version.V4, Purpose.Public { keyV4Public }),
        ).map {
            Arguments.of(it.first, it.second)
        }.stream()
    }

    @Test
    fun decodeFooter_catchesIllegalArgumentException() {
        val json = mockk<Json>()
        every {
            json.decodeFromString<ClaimFooter>(any(), any())
        } throws IllegalArgumentException()

        try {
            shouldNotThrow<IllegalArgumentException> {
                (json.decodeFooter(FooterOptions(), "abc") as StringFooter).value shouldBe "abc"
            }
        } finally {
            unmockkAll()
        }
    }

    @ParameterizedTest
    @MethodSource("allServiceConfigurations")
    fun decodeFooter_paddedBase64Fails(version: Version, purpose: Purpose) {
        val invalid = Base64.UrlSafe.encode("has padding".toByteArray())
        val purposeStr = when (purpose) {
            is Purpose.Local -> "local"
            is Purpose.Public -> "public"
        }
        val token = "${version.toString().lowercase()}.$purposeStr.a.$invalid"
        val service = tokenService(version, purpose)

        val ex = shouldThrow<PasetoParseException> {
            service.decode(token) shouldBe null
        }
        ex.reason shouldBe PasetoParseException.Reason.INVALID_BASE64
    }

    @Test
    fun insecureGetFooter_paddedBase64Fails() {
        val invalid = Base64.UrlSafe.encode("has padding".toByteArray())
        val token = "v4.local.a.$invalid"
        val service = tokenService(Version.V4, Purpose.Local { keyV4Local })

        val ex = shouldThrow<PasetoParseException> {
            service.insecureGetFooter(token) shouldBe null
        }
        ex.reason shouldBe PasetoParseException.Reason.INVALID_BASE64
    }

    @Test
    fun `ClaimFooter claimsJson returns footer claims object`() {
        val footer = footer {
            keyId = "kid-1"
            claims {
                put("custom", "value")
            }
        }

        val json = footer.claimsJson()
        json.containsKey("custom") shouldBe true
    }

    @Test
    fun `TaintedClaimFooter claimsJson returns footer claims object`() {
        val service = tokenService(Version.V4, Purpose.Local { keyV4Local })
        val token = token {
            issuedAt = Instant.now()
            expiresAt = Instant.now().plus(Duration.ofHours(1))
            footer {
                claims {
                    put("custom", "value")
                }
            }
        }

        val encoded = service.encode(token)
        val tainted = service.insecureGetFooter(encoded) as TaintedClaimFooter

        val json = tainted.claimsJson()
        json.containsKey("custom") shouldBe true
    }

    @Nested
    inner class TokenVerificationTests {
        @ParameterizedTest
        @MethodSource("net.aholbrook.paseto.FooterSerdeTests#allServiceConfigurations")
        fun `errors on footer mismatch`(version: Version, purpose: Purpose) {
            val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
            val service = tokenService(version, purpose) {
                rules {
                    issuedInPast = IssuedInPast(clock = clock)
                    notExpired = NotExpired(clock = clock)
                }
            }
            val token = token {
                issuedAt = clock.instant()
                expiresAt = clock.instant().plus(Duration.ofHours(1))
                footer("test footer value")
            }

            val encoded = service.encode(token)
            shouldThrow<IncorrectFooterException> {
                service.decode(encoded, footer("wrong"))
            }
        }

        @ParameterizedTest
        @MethodSource("net.aholbrook.paseto.FooterSerdeTests#allServiceConfigurations")
        fun `token footer verification does not apply if argument is not given`(version: Version, purpose: Purpose) {
            val service = tokenService(version, purpose)
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("just a string")
            }

            val encoded = service.encode(token)
            shouldNotThrow<IncorrectFooterException> {
                service.decode(encoded)
            }
        }

        @ParameterizedTest
        @MethodSource("net.aholbrook.paseto.FooterSerdeTests#allServiceConfigurations")
        fun `token footer verification applies for empty string (no footer)`(version: Version, purpose: Purpose) {
            val service = tokenService(version, purpose)
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("just a string")
            }

            val encoded = service.encode(token)
            shouldThrow<IncorrectFooterException> {
                service.decode(encoded, footer(""))
            }
        }

        @ParameterizedTest
        @MethodSource("net.aholbrook.paseto.FooterSerdeTests#allServiceConfigurations")
        fun `token footer verification works for string footer`(version: Version, purpose: Purpose) {
            val service = tokenService(version, purpose)
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("just a string")
            }

            val encoded = service.encode(token)
            val decoded = service.decode(encoded, token.footer)
            decoded.footer shouldBe token.footer
        }

        @ParameterizedTest
        @MethodSource("net.aholbrook.paseto.FooterSerdeTests#allServiceConfigurations")
        fun `token footer verification works for claim footer`(version: Version, purpose: Purpose) {
            val service = tokenService(version, purpose)
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer {
                    keyId = "key-3"
                    wrappedKey = "invalid"
                    claims {
                        put("custom", "also works?")
                    }
                }
            }

            val encoded = service.encode(token)
            val decoded = service.decode(encoded, token.footer)
            decoded.footer shouldBe token.footer
        }

        @ParameterizedTest
        @MethodSource("net.aholbrook.paseto.FooterSerdeTests#allServiceConfigurations")
        fun `token footer verification catches errors in string footers`(version: Version, purpose: Purpose) {
            val service = tokenService(version, purpose)
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("just a string")
            }
            val expectedFooter = footer("not the string")

            val encoded = service.encode(token)
            shouldThrow<IncorrectFooterException> {
                service.decode(encoded, expectedFooter)
            }
        }

        @ParameterizedTest
        @MethodSource("net.aholbrook.paseto.FooterSerdeTests#allServiceConfigurations")
        fun `token footer verification catches errors in claim footers`(version: Version, purpose: Purpose) {
            val service = tokenService(version, purpose)
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer {
                    keyId = "key-3"
                    wrappedKey = "invalid"
                    claims {
                        put("custom", "also works?")
                    }
                }
            }
            val expectedFooter = footer { }

            val encoded = service.encode(token)
            shouldThrow<IncorrectFooterException> {
                service.decode(encoded, expectedFooter)
            }
        }
    }

    @Nested
    inner class FooterParseModeTests {
        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `token footer parse mode auto reverts to string if not a json object`(footerApi: FooterApi) {
            val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
            val service = tokenService(Version.V4, Purpose.Public { keyV4Public }) {
                rules {
                    issuedInPast = IssuedInPast(clock = clock)
                    notExpired = NotExpired(clock = clock)
                }
                footerOptions {
                    parseMode = FooterParseMode.AUTO
                }
            }
            val token = token {
                issuedAt = clock.instant()
                expiresAt = clock.instant().plus(Duration.ofHours(1))
                footer("[1,2,3]")
            }

            val encoded = service.encode(token)

            when (footerApi) {
                FooterApi.DECODE -> {
                    val decoded = service.decode(encoded)
                    decoded.footer shouldBe footer("[1,2,3]")
                }

                FooterApi.INSECURE_GET_FOOTER -> {
                    val decodedFooter = service.insecureGetFooter(encoded)
                    decodedFooter shouldBe footer("[1,2,3]").taint()
                }
            }
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `token footer parse mode auto handles invalid json`(footerApi: FooterApi) {
            val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                rules {
                    issuedInPast = IssuedInPast(clock = clock)
                    notExpired = NotExpired(clock = clock)
                }
            }
            val token = token {
                issuedAt = clock.instant()
                expiresAt = clock.instant().plus(Duration.ofHours(1))
                footer("{")
            }

            val encoded = service.encode(token)

            when (footerApi) {
                FooterApi.DECODE -> {
                    val decoded = service.decode(encoded)
                    decoded.footer shouldBe footer("{")
                }

                FooterApi.INSECURE_GET_FOOTER -> {
                    val decodedFooter = service.insecureGetFooter(encoded)
                    decodedFooter shouldBe footer("{").taint()
                }
            }
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `footer parse mode auto validation rejects footer that exceeds max length`(footerApi: FooterApi) {
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("123456")
            }
            val encoded = tokenService(Version.V4, Purpose.Local { keyV4Local }).encode(token)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                footerOptions {
                    maxLength = 5
                }
            }

            val ex = shouldThrow<FooterExceedsMaxLengthException> {
                when (footerApi) {
                    FooterApi.DECODE -> service.decode(encoded)
                    FooterApi.INSECURE_GET_FOOTER -> service.insecureGetFooter(encoded)
                }
            }
            ex.length shouldBe 6
            ex.max shouldBe 5
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `footer parse mode auto validation rejects footer that exceeds max depth`(footerApi: FooterApi) {
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("{\"a\":{\"b\":1}}")
            }
            val encoded = tokenService(Version.V4, Purpose.Local { keyV4Local }).encode(token)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                footerOptions {
                    maxDepth = 1
                }
            }

            val ex = shouldThrow<FooterExceedsMaxDepthException> {
                when (footerApi) {
                    FooterApi.DECODE -> service.decode(encoded)
                    FooterApi.INSECURE_GET_FOOTER -> service.insecureGetFooter(encoded)
                }
            }
            ex.depth shouldBe 2
            ex.max shouldBe 1
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `footer parse mode auto validation rejects footer that exceeds max keys`(footerApi: FooterApi) {
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("{\"a\":1,\"b\":2}")
            }
            val encoded = tokenService(Version.V4, Purpose.Local { keyV4Local }).encode(token)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                footerOptions {
                    maxKeys = 1
                }
            }

            val ex = shouldThrow<FooterExceedsMaxKeysException> {
                when (footerApi) {
                    FooterApi.DECODE -> service.decode(encoded)
                    FooterApi.INSECURE_GET_FOOTER -> service.insecureGetFooter(encoded)
                }
            }
            ex.keys shouldBe 2
            ex.max shouldBe 1
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `parse mode auto can decode a string footer`(footerApi: FooterApi) {
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local })
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("just a string")
            }

            val encoded = service.encode(token)

            when (footerApi) {
                FooterApi.DECODE -> {
                    val decoded = service.decode(encoded)
                    (decoded.footer as StringFooter).value shouldBe "just a string"
                    decoded.footer shouldBe token.footer
                }

                FooterApi.INSECURE_GET_FOOTER -> {
                    val taintedFooter = service.insecureGetFooter(encoded)
                    (taintedFooter as TaintedStringFooter).value shouldBe "just a string"
                    taintedFooter shouldBe token.footer.taint()
                }
            }
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `parse mode auto can decode a claim footer`(footerApi: FooterApi) {
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local })
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer {
                    keyId = "key-3"
                    wrappedKey = "invalid"
                    claims {
                        put("custom", "also works?")
                    }
                }
            }

            val encoded = service.encode(token)

            when (footerApi) {
                FooterApi.DECODE -> {
                    val decoded = service.decode(encoded)
                    with(decoded.footer as ClaimFooter) {
                        keyId shouldBe "key-3"
                        wrappedKey shouldBe "invalid"
                        claims["custom"]?.stringOrNull shouldBe "also works?"
                    }
                    decoded.footer shouldBe token.footer
                }

                FooterApi.INSECURE_GET_FOOTER -> {
                    val taintedFooter = service.insecureGetFooter(encoded)
                    with(taintedFooter as TaintedClaimFooter) {
                        keyId shouldBe "key-3"
                        wrappedKey shouldBe "invalid"
                        claims["custom"]?.stringOrNull shouldBe "also works?"
                    }
                    taintedFooter shouldBe token.footer.taint()
                }
            }
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `parse mode auto only applies validations to object-like footer`(footerApi: FooterApi) {
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                footerOptions {
                    parseMode = FooterParseMode.AUTO
                    maxKeys = 2
                }
            }
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("::::")
            }

            val encoded = service.encode(token)

            when (footerApi) {
                FooterApi.DECODE -> {
                    val decoded = service.decode(encoded)
                    decoded.footer shouldBe token.footer
                }

                FooterApi.INSECURE_GET_FOOTER -> {
                    val decodedFooter = service.insecureGetFooter(encoded)
                    decodedFooter shouldBe token.footer.taint()
                }
            }
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `token footer parse mode claims errors on invalid json`(footerApi: FooterApi) {
            val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                rules {
                    issuedInPast = IssuedInPast(clock = clock)
                    notExpired = NotExpired(clock = clock)
                }
                footerOptions {
                    parseMode = FooterParseMode.CLAIMS
                }
            }
            val token = token {
                issuedAt = clock.instant()
                expiresAt = clock.instant().plus(Duration.ofHours(1))
                footer("{")
            }

            val encoded = service.encode(token)

            shouldThrow<FooterJsonParseException> {
                when (footerApi) {
                    FooterApi.DECODE -> service.decode(encoded)
                    FooterApi.INSECURE_GET_FOOTER -> service.insecureGetFooter(encoded)
                }
            }
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `footer parse mode claims validation rejects footer that exceeds max length`(footerApi: FooterApi) {
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("123456")
            }
            val encoded = tokenService(Version.V4, Purpose.Local { keyV4Local }).encode(token)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                footerOptions {
                    parseMode = FooterParseMode.CLAIMS
                    maxLength = 5
                }
            }

            val ex = shouldThrow<FooterExceedsMaxLengthException> {
                when (footerApi) {
                    FooterApi.DECODE -> service.decode(encoded)
                    FooterApi.INSECURE_GET_FOOTER -> service.insecureGetFooter(encoded)
                }
            }
            ex.length shouldBe 6
            ex.max shouldBe 5
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `footer parse mode claims validation rejects footer that exceeds max depth`(footerApi: FooterApi) {
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("{\"a\":{\"b\":1}}")
            }
            val encoded = tokenService(Version.V4, Purpose.Local { keyV4Local }).encode(token)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                footerOptions {
                    parseMode = FooterParseMode.CLAIMS
                    maxDepth = 1
                }
            }

            val ex = shouldThrow<FooterExceedsMaxDepthException> {
                when (footerApi) {
                    FooterApi.DECODE -> service.decode(encoded)
                    FooterApi.INSECURE_GET_FOOTER -> service.insecureGetFooter(encoded)
                }
            }
            ex.depth shouldBe 2
            ex.max shouldBe 1
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `footer parse mode claims validation rejects footer that exceeds max keys`(footerApi: FooterApi) {
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("{\"a\":1,\"b\":2}")
            }
            val encoded = tokenService(Version.V4, Purpose.Local { keyV4Local }).encode(token)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                footerOptions {
                    parseMode = FooterParseMode.CLAIMS
                    maxKeys = 1
                }
            }

            val ex = shouldThrow<FooterExceedsMaxKeysException> {
                when (footerApi) {
                    FooterApi.DECODE -> service.decode(encoded)
                    FooterApi.INSECURE_GET_FOOTER -> service.insecureGetFooter(encoded)
                }
            }
            ex.keys shouldBe 2
            ex.max shouldBe 1
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `token footer parse mode string ignores invalid json`(footerApi: FooterApi) {
            val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                rules {
                    issuedInPast = IssuedInPast(clock = clock)
                    notExpired = NotExpired(clock = clock)
                }
                footerOptions {
                    parseMode = FooterParseMode.STRING
                }
            }
            val token = token {
                issuedAt = clock.instant()
                expiresAt = clock.instant().plus(Duration.ofHours(1))
                footer("{")
            }

            val encoded = service.encode(token)

            when (footerApi) {
                FooterApi.DECODE -> {
                    val decoded = service.decode(encoded)
                    decoded.footer shouldBe footer("{")
                }

                FooterApi.INSECURE_GET_FOOTER -> {
                    val decodedFooter = service.insecureGetFooter(encoded)
                    decodedFooter shouldBe footer("{").taint()
                }
            }
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `footer parse mode string validation rejects footer that exceeds max length`(footerApi: FooterApi) {
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("123456")
            }
            val encoded = tokenService(Version.V4, Purpose.Local { keyV4Local }).encode(token)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                footerOptions {
                    parseMode = FooterParseMode.STRING
                    maxLength = 5
                }
            }

            val ex = shouldThrow<FooterExceedsMaxLengthException> {
                when (footerApi) {
                    FooterApi.DECODE -> service.decode(encoded)
                    FooterApi.INSECURE_GET_FOOTER -> service.insecureGetFooter(encoded)
                }
            }
            ex.length shouldBe 6
            ex.max shouldBe 5
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `footer parse mode string ignores max depth`(footerApi: FooterApi) {
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("{\"a\":{\"b\":1}}")
            }
            val encoded = tokenService(Version.V4, Purpose.Local { keyV4Local }).encode(token)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                footerOptions {
                    parseMode = FooterParseMode.STRING
                    maxDepth = 1
                }
            }

            when (footerApi) {
                FooterApi.DECODE -> {
                    val decoded = service.decode(encoded)
                    decoded.footer shouldBe token.footer
                }

                FooterApi.INSECURE_GET_FOOTER -> {
                    val decodedFooter = service.insecureGetFooter(encoded)
                    decodedFooter shouldBe token.footer.taint()
                }
            }
        }

        @ParameterizedTest
        @EnumSource(FooterApi::class)
        fun `footer parse mode string ignores max keys`(footerApi: FooterApi) {
            val token = token {
                issuedAt = Instant.now()
                expiresAt = Instant.now().plus(Duration.ofHours(1))
                footer("{\"a\":1,\"b\":2}")
            }
            val encoded = tokenService(Version.V4, Purpose.Local { keyV4Local }).encode(token)
            val service = tokenService(Version.V4, Purpose.Local { keyV4Local }) {
                footerOptions {
                    parseMode = FooterParseMode.STRING
                    maxKeys = 1
                }
            }

            when (footerApi) {
                FooterApi.DECODE -> {
                    val decoded = service.decode(encoded)
                    decoded.footer shouldBe token.footer
                }

                FooterApi.INSECURE_GET_FOOTER -> {
                    val decodedFooter = service.insecureGetFooter(encoded)
                    decodedFooter shouldBe token.footer.taint()
                }
            }
        }
    }
}
