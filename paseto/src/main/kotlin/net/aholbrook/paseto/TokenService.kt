@file:Suppress("DuplicatedCode")

package net.aholbrook.paseto

import kotlinx.serialization.json.Json
import net.aholbrook.paseto.exception.CannotSignWithoutSecretKey
import net.aholbrook.paseto.exception.FooterExceedsMaxDepthException
import net.aholbrook.paseto.exception.FooterExceedsMaxKeysException
import net.aholbrook.paseto.exception.FooterExceedsMaxLengthException
import net.aholbrook.paseto.exception.FooterJsonParseException
import net.aholbrook.paseto.exception.ImplicitAssertionsNotSupportedException
import net.aholbrook.paseto.protocol.key.KeyPair
import net.aholbrook.paseto.protocol.Paseto
import net.aholbrook.paseto.protocol.key.SymmetricKey
import net.aholbrook.paseto.protocol.Version
import net.aholbrook.paseto.protocol.extractFooter
import net.aholbrook.paseto.protocol.jsonCountDepthAndKeys
import net.aholbrook.paseto.rules.Rule
import net.aholbrook.paseto.rules.Rules
import net.aholbrook.paseto.rules.RulesBuilder
import net.aholbrook.paseto.rules.rules
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

sealed interface Purpose {
    class Public(val keyProvider: () -> KeyPair) : Purpose
    class Local(val keyProvider: () -> SymmetricKey) : Purpose
}

/**
 * Determines how token footer text is interpreted when decoding.
 *
 * - `AUTO`: Treat object-like footer text (`{...}`) as JSON claims when possible;
 *   otherwise fall back to a plain string footer.
 * - `CLAIMS`: Require a valid JSON claims footer and fail if parsing/validation fails.
 * - `STRING`: Always treat footer text as plain string data (no claims parsing).
 */
enum class FooterParseMode {
    /**
     * Parse object-like footer text as claims, throwing on depth/key limit violations and falling back to
     * [StringFooter] on parse failure.
     */
    AUTO,

    /**
     * Require footer to be valid claims JSON; throw on parse/validation errors.
     */
    CLAIMS,

    /**
     * Always decode footer as plain string.
     */
    STRING,
}

internal data class FooterOptions(
    val parseMode: FooterParseMode = FooterParseMode.AUTO,
    val maxLength: Int = 8192,
    val maxDepth: Int = 2,
    val maxKeys: Int = 512,
)

@PasetoDslMarker
class FooterOptionsBuilder @PublishedApi internal constructor() {
    var parseMode: FooterParseMode = FooterParseMode.AUTO
    var maxLength: Int = 8192
    var maxDepth: Int = 2
    var maxKeys: Int = 512

    internal fun build(): FooterOptions = FooterOptions(
        parseMode = parseMode,
        maxLength = maxLength,
        maxDepth = maxDepth,
        maxKeys = maxKeys,
    )
}

@PasetoDslMarker
class TokenServiceBuilder @PublishedApi internal constructor() {
    private var rules: Rules = rules()
    private var footerOptions: FooterOptions = FooterOptions()

    fun rules(init: RulesBuilder.() -> Unit) {
        rules = rules(rules, init)
    }

    fun rules(rules: Rules) {
        this.rules = rules
    }

    fun footerOptions(init: FooterOptionsBuilder.() -> Unit) {
        val current = footerOptions
        footerOptions = FooterOptionsBuilder()
            .apply {
                parseMode = current.parseMode
                maxLength = current.maxLength
                maxDepth = current.maxDepth
                maxKeys = current.maxKeys
            }
            .apply(init)
            .build()
    }

    @PublishedApi
    internal fun build(version: Version, purpose: Purpose): TokenService = purpose.let { purpose ->
        when (purpose) {
            is Purpose.Public -> {
                PublicTokenService(
                    paseto = version.paseto,
                    keyProvider = purpose.keyProvider,
                    footerOptions = footerOptions,
                    rules = rules,
                )
            }

            is Purpose.Local -> {
                LocalTokenService(
                    paseto = version.paseto,
                    keyProvider = purpose.keyProvider,
                    footerOptions = footerOptions,
                    rules = rules,
                )
            }
        }
    }
}

@OptIn(ExperimentalContracts::class)
inline fun tokenService(version: Version, purpose: Purpose, init: TokenServiceBuilder.() -> Unit = {}): TokenService {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
    return TokenServiceBuilder().apply(init).build(version, purpose)
}

sealed interface TokenService {
    fun encode(token: PasetoToken, implicitAssertion: String = ""): String
    fun decode(token: String, footer: PasetoFooter = EmptyFooter, implicitAssertion: String = ""): PasetoToken

    /**
     * Decode the token's footer without verifying the token.
     *
     * This is useful if the token footer contains data required to decode the token. Returns an [TaintedPasetoFooter]
     * to prevent misuse as this footer should **never** be used when checking the footer during decoding.
     *
     * @param [token] paseto token to decode the footer of.
     * @return [TaintedPasetoFooter] with the decoded footer contents.
     */
    fun insecureGetFooter(token: String): TaintedPasetoFooter?
}

internal class LocalTokenService internal constructor(
    private val paseto: Paseto,
    private val keyProvider: () -> SymmetricKey,
    private val rules: Rules,
    private val footerOptions: FooterOptions,
    private val json: Json = Json { explicitNulls = false },
) : TokenService {
    override fun encode(token: PasetoToken, implicitAssertion: String): String {
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        rules.verifyAll(token, Rule.Mode.ENCODE)
        val encoded = json.encodeToString(PasetoTokenSerializer, token)
        val encodedFooter = json.encodeFooter(footerOptions, token.footer)
        return paseto.encrypt(
            m = encoded.toByteArray(Charsets.UTF_8),
            key = keyProvider(),
            footer = encodedFooter ?: "",
            implicitAssertion = implicitAssertion,
        )
    }

    override fun decode(token: String, footer: PasetoFooter, implicitAssertion: String): PasetoToken {
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        val (encoded, footer) = paseto.decrypt(
            token = token,
            key = keyProvider(),
            footer = json.encodeFooter(footerOptions, footer),
            implicitAssertion = implicitAssertion,
        )
        var decoded = json.decodeFromString(PasetoTokenSerializer, encoded)
        json.decodeFooter(footerOptions, footer).let { footer -> decoded = decoded.copy(footer = footer) }

        rules.verifyAll(decoded, Rule.Mode.DECODE)
        return decoded
    }

    override fun insecureGetFooter(token: String): TaintedPasetoFooter? =
        json.decodeFooter(footerOptions, extractFooter(token)).taint()
}

internal class PublicTokenService internal constructor(
    private val paseto: Paseto,
    private val keyProvider: () -> KeyPair,
    private val rules: Rules,
    private val footerOptions: FooterOptions,
    private val json: Json = Json { explicitNulls = false },
) : TokenService {
    override fun encode(token: PasetoToken, implicitAssertion: String): String {
        // TODO expand service-test-vectors for v4 with implicit assertions
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        rules.verifyAll(token, Rule.Mode.ENCODE)
        val encoded = json.encodeToString(PasetoTokenSerializer, token)
        val encodedFooter = json.encodeFooter(footerOptions, token.footer)
        val keyPair = keyProvider()
        if (keyPair.secretKey == null) {
            throw CannotSignWithoutSecretKey()
        }
        return paseto.sign(
            m = encoded.toByteArray(Charsets.UTF_8),
            secretKey = keyPair.secretKey,
            footer = encodedFooter ?: "",
            implicitAssertion = implicitAssertion,
        )
    }

    override fun decode(token: String, footer: PasetoFooter, implicitAssertion: String): PasetoToken {
        // TODO expand service-test-vectors for v4 with implicit assertions
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        val (encoded, footer) = paseto.verify(
            token = token,
            publicKey = keyProvider().publicKey,
            footer = json.encodeFooter(footerOptions, footer),
            implicitAssertion = implicitAssertion,
        )
        var decoded = json.decodeFromString(PasetoTokenSerializer, encoded)
        json.decodeFooter(footerOptions, footer).let { footer -> decoded = decoded.copy(footer = footer) }

        rules.verifyAll(decoded, Rule.Mode.DECODE)
        return decoded
    }

    override fun insecureGetFooter(token: String): TaintedPasetoFooter? =
        json.decodeFooter(footerOptions, extractFooter(token)).taint()
}

private fun String.isJsonObject(): Boolean = trim().let { it.startsWith("{") && it.endsWith("}") }

private fun FooterOptions.validateFooter(footer: String?) {
    if (footer == null) return

    if (footer.length > maxLength) throw FooterExceedsMaxLengthException(footer.length, maxLength)
    if (parseMode == FooterParseMode.STRING) return
    if (parseMode == FooterParseMode.AUTO && !footer.isJsonObject()) return

    val (depth, keys) = jsonCountDepthAndKeys(footer)
    if (depth > maxDepth) throw FooterExceedsMaxDepthException(depth, maxDepth)
    if (keys > maxKeys) throw FooterExceedsMaxKeysException(keys, maxKeys)
}

private fun Json.encodeFooter(footerOptions: FooterOptions, footer: PasetoFooter): String? {
    val encoded = when (footer) {
        is EmptyFooter -> null
        is ClaimFooter -> encodeToString(ClaimFooterSerializer, footer)
        is StringFooter -> footer.value
    }

    footerOptions.validateFooter(encoded)
    return encoded
}

internal fun Json.decodeFooter(footerOptions: FooterOptions, footer: String): PasetoFooter {
    footerOptions.validateFooter(footer)

    return when (footerOptions.parseMode) {
        FooterParseMode.AUTO -> try {
            decodeFromString(ClaimFooterSerializer, footer)
        } catch (_: Exception) {
            StringFooter(footer)
        }

        FooterParseMode.CLAIMS -> try {
            decodeFromString(ClaimFooterSerializer, footer)
        } catch (ex: Exception) {
            throw FooterJsonParseException(ex.message, ex)
        }

        FooterParseMode.STRING -> StringFooter(footer)
    }
}
