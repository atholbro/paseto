@file:Suppress("DuplicatedCode")

package net.aholbrook.paseto

import kotlinx.serialization.json.Json
import net.aholbrook.paseto.exception.CannotSignWithoutSecretKey
import net.aholbrook.paseto.exception.ImplicitAssertionsNotSupportedException
import net.aholbrook.paseto.protocol.Paseto
import net.aholbrook.paseto.protocol.Version
import net.aholbrook.paseto.protocol.extractFooter
import net.aholbrook.paseto.protocol.key.KeyPair
import net.aholbrook.paseto.protocol.key.SymmetricKey
import net.aholbrook.paseto.rules.Rule
import net.aholbrook.paseto.rules.Rules
import net.aholbrook.paseto.rules.RulesBuilder
import net.aholbrook.paseto.rules.rules
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

/**
 * Selects whether a service operates in `local` (symmetric) or `public` (asymmetric) mode.
 */
sealed interface Purpose {
    /**
     * Public-token mode (`v*.public`).
     *
     * The key provider receives the tainted footer so callers can route to the correct key pair
     * (for example by `kid`).
     *
     * @property keyProvider Returns the [KeyPair] used for the current token operation.
     */
    class Public(val keyProvider: (footer: TaintedFooter) -> KeyPair) : Purpose

    /**
     * Local-token mode (`v*.local`).
     *
     * The key provider receives the tainted footer so callers can route to the correct symmetric
     * key (for example by `kid`).
     *
     * @property keyProvider Returns the [SymmetricKey] used for the current token operation.
     */
    class Local(val keyProvider: (footer: TaintedFooter) -> SymmetricKey) : Purpose
}

/**
 * Builder DSL for creating a [TokenService].
 */
@PasetoDslMarker
class TokenServiceBuilder @PublishedApi internal constructor() {
    private var rules: Rules = rules()
    private var footerOptions: FooterOptions = FooterOptions()

    /**
     * Mutate the current [rules] set using the [RulesBuilder] DSL.
     *
     * @param init Rule mutations to apply.
     */
    fun rules(init: RulesBuilder.() -> Unit) {
        rules = rules(rules, init)
    }

    /**
     * Replace the current rules with an externally constructed [Rules] instance.
     *
     * @param rules Rule set that should replace existing configuration.
     */
    fun rules(rules: Rules) {
        this.rules = rules
    }

    /**
     * Configure footer parsing/validation options used by decode and insecure footer reads.
     *
     * @param init Footer option mutations to apply.
     */
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

/**
 * Create a token service for a PASETO [version] and [purpose].
 *
 * @param version Protocol [Version] used for encode/decode.
 * @param purpose Local/public service [Purpose] and key provider.
 * @param init Optional builder configuration.
 * @return Configured [TokenService].
 */
@OptIn(ExperimentalContracts::class)
inline fun tokenService(version: Version, purpose: Purpose, init: TokenServiceBuilder.() -> Unit = {}): TokenService {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
    return TokenServiceBuilder().apply(init).build(version, purpose)
}

sealed interface TokenService {
    /**
     * Encode a [token] into a PASETO string.
     *
     * For v3/v4, [implicitAssertion] is authenticated but not included in the token body.
     * v1/v2 do not support [implicitAssertion] and will throw [ImplicitAssertionsNotSupportedException].
     *
     * @param token Token value to encode.
     * @param implicitAssertion Optional implicit assertion for v3/v4 tokens.
     * @return Encoded PASETO token.
     */
    fun encode(token: Token, implicitAssertion: String = ""): String

    /**
     * Decode and verify a PASETO [token].
     *
     * If [footer] is provided, it must match the token footer exactly.
     *
     * For v3/v4, [implicitAssertion] is authenticated but not included in the token body.
     * v1/v2 do not support [implicitAssertion] and will throw [ImplicitAssertionsNotSupportedException].
     *
     * @param token Encoded PASETO token.
     * @param footer Optional expected footer for strict footer verification.
     * @param implicitAssertion Optional implicit assertion for v3/v4 tokens.
     * @return Decoded [Token] after cryptographic verification.
     */
    fun decode(token: String, footer: Footer? = null, implicitAssertion: String = ""): Token

    /**
     * Decode the token's footer without verifying the token.
     *
     * This is useful if the token footer contains data required to decode the token. Returns a [TaintedFooter]
     * to prevent misuse as this footer should **never** be used when checking the footer during decoding.
     *
     * @param token PASETO token to inspect.
     * @return [TaintedFooter] with the decoded footer contents.
     */
    fun insecureGetFooter(token: String): TaintedFooter
}

internal class LocalTokenService internal constructor(
    private val paseto: Paseto,
    private val keyProvider: (footer: TaintedFooter) -> SymmetricKey,
    private val rules: Rules,
    private val footerOptions: FooterOptions,
    private val json: Json = Json { explicitNulls = false },
) : TokenService {
    override fun encode(token: Token, implicitAssertion: String): String {
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        rules.verifyAll(token, Rule.Mode.ENCODE)
        val encoded = json.encodeToString(PasetoTokenSerializer, token)
        val encodedFooter = json.encodeFooter(footerOptions, token.footer)
        return paseto.encrypt(
            m = encoded.toByteArray(Charsets.UTF_8),
            key = keyProvider(token.footer.taint()),
            footer = encodedFooter,
            implicitAssertion = implicitAssertion,
        )
    }

    override fun decode(token: String, footer: Footer?, implicitAssertion: String): Token {
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        val (encoded, footer) = paseto.decrypt(
            token = token,
            key = keyProvider(insecureGetFooter(token)),
            footer = footer?.let { json.encodeFooter(footerOptions, it) },
            implicitAssertion = implicitAssertion,
        )
        var decoded = json.decodeFromString(PasetoTokenSerializer, encoded)
        json.decodeFooter(footerOptions, footer).let { footer -> decoded = decoded.copy(footer = footer) }

        rules.verifyAll(decoded, Rule.Mode.DECODE)
        return decoded
    }

    override fun insecureGetFooter(token: String): TaintedFooter =
        json.decodeFooter(footerOptions, extractFooter(token)).taint()
}

internal class PublicTokenService internal constructor(
    private val paseto: Paseto,
    private val keyProvider: (footer: TaintedFooter) -> KeyPair,
    private val rules: Rules,
    private val footerOptions: FooterOptions,
    private val json: Json = Json { explicitNulls = false },
) : TokenService {
    override fun encode(token: Token, implicitAssertion: String): String {
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        rules.verifyAll(token, Rule.Mode.ENCODE)
        val encoded = json.encodeToString(PasetoTokenSerializer, token)
        val encodedFooter = json.encodeFooter(footerOptions, token.footer)
        val keyPair = keyProvider(token.footer.taint())
        if (keyPair.secretKey == null) {
            throw CannotSignWithoutSecretKey()
        }
        return paseto.sign(
            m = encoded.toByteArray(Charsets.UTF_8),
            secretKey = keyPair.secretKey,
            footer = encodedFooter,
            implicitAssertion = implicitAssertion,
        )
    }

    override fun decode(token: String, footer: Footer?, implicitAssertion: String): Token {
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        val (encoded, footer) = paseto.verify(
            token = token,
            publicKey = keyProvider(insecureGetFooter(token)).publicKey,
            footer = footer?.let { json.encodeFooter(footerOptions, it) },
            implicitAssertion = implicitAssertion,
        )
        var decoded = json.decodeFromString(PasetoTokenSerializer, encoded)
        json.decodeFooter(footerOptions, footer).let { footer -> decoded = decoded.copy(footer = footer) }

        rules.verifyAll(decoded, Rule.Mode.DECODE)
        return decoded
    }

    override fun insecureGetFooter(token: String): TaintedFooter =
        json.decodeFooter(footerOptions, extractFooter(token)).taint()
}
