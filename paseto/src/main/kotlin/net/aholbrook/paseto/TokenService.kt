@file:Suppress("DuplicatedCode")

package net.aholbrook.paseto

import kotlinx.serialization.json.Json
import net.aholbrook.paseto.exception.CannotSignWithoutSecretKey
import net.aholbrook.paseto.exception.FooterExceedsMaxDepthException
import net.aholbrook.paseto.exception.FooterExceedsMaxKeysException
import net.aholbrook.paseto.exception.FooterExceedsMaxLengthException
import net.aholbrook.paseto.exception.ImplicitAssertionsNotSupportedException
import net.aholbrook.paseto.protocol.KeyPair
import net.aholbrook.paseto.protocol.Paseto
import net.aholbrook.paseto.protocol.SymmetricKey
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

internal data class FooterValidation(val maxLength: Int = 8192, val maxDepth: Int = 2, val maxKeys: Int = 512) {
    operator fun invoke(footer: String) {
        if (footer.length > maxLength) throw FooterExceedsMaxLengthException(footer.length, maxLength)
        val (depth, keys) = jsonCountDepthAndKeys(footer)

        if (depth > maxDepth) throw FooterExceedsMaxDepthException(depth, maxDepth)
        if (keys > maxKeys) throw FooterExceedsMaxKeysException(keys, maxKeys)
    }
}

@PasetoDslMarker
class FooterValidationBuilder @PublishedApi internal constructor() {
    var maxLength: Int = 8192
    var maxDepth: Int = 2
    var maxKeys: Int = 512

    @PublishedApi
    internal fun build(): FooterValidation = FooterValidation(
        maxLength = maxLength,
        maxDepth = maxDepth,
        maxKeys = maxKeys,
    )
}

@PasetoDslMarker
class TokenServiceBuilder @PublishedApi internal constructor() {
    private var rules: Rules = rules()
    private var footerValidation: FooterValidation = FooterValidation()

    fun rules(init: RulesBuilder.() -> Unit) {
        rules = rules(rules, init)
    }

    fun rules(rules: Rules) {
        this.rules = rules
    }

    fun footerValidation(init: FooterValidationBuilder.() -> Unit) {
        val current = footerValidation
        footerValidation = FooterValidationBuilder()
            .apply {
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
                    footerValidation = footerValidation,
                    rules = rules,
                )
            }

            is Purpose.Local -> {
                LocalTokenService(
                    paseto = version.paseto,
                    keyProvider = purpose.keyProvider,
                    footerValidation = footerValidation,
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
    fun decode(token: String, footer: PasetoFooter = StringFooter(""), implicitAssertion: String = ""): PasetoToken

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
    private val footerValidation: FooterValidation,
    private val json: Json = Json { explicitNulls = false },
) : TokenService {
    override fun encode(token: PasetoToken, implicitAssertion: String): String {
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        rules.verifyAll(token, Rule.Mode.ENCODE)
        val encoded = json.encodeToString(PasetoTokenSerializer, token)
        val encodedFooter = json.encodeFooter(token.footer)
        footerValidation(encoded)
        return paseto.encrypt(encoded.toByteArray(Charsets.UTF_8), keyProvider(), encodedFooter, implicitAssertion)
    }

    override fun decode(token: String, footer: PasetoFooter, implicitAssertion: String): PasetoToken {
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        val (encoded, footer) = paseto.decrypt(token, keyProvider(), json.encodeFooter(footer), implicitAssertion)
        var decoded = json.decodeFromString(PasetoTokenSerializer, encoded)
        json.decodeFooter(footerValidation, footer).let { footer -> decoded = decoded.copy(footer = footer) }

        rules.verifyAll(decoded, Rule.Mode.DECODE)
        return decoded
    }

    override fun insecureGetFooter(token: String): TaintedPasetoFooter? =
        json.decodeFooter(footerValidation, extractFooter(token)).taint()
}

internal class PublicTokenService internal constructor(
    private val paseto: Paseto,
    private val keyProvider: () -> KeyPair,
    private val rules: Rules,
    private val footerValidation: FooterValidation,
    private val json: Json = Json { explicitNulls = false },
) : TokenService {
    override fun encode(token: PasetoToken, implicitAssertion: String): String {
        // TODO expand service-test-vectors for v4 with implicit assertions
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        rules.verifyAll(token, Rule.Mode.ENCODE)
        val encoded = json.encodeToString(PasetoTokenSerializer, token)
        val encodedFooter = json.encodeFooter(token.footer)
        footerValidation(encoded)
        val keyPair = keyProvider()
        if (keyPair.secretKey == null) {
            throw CannotSignWithoutSecretKey()
        }
        return paseto.sign(encoded.toByteArray(Charsets.UTF_8), keyPair.secretKey, encodedFooter, implicitAssertion)
    }

    override fun decode(token: String, footer: PasetoFooter, implicitAssertion: String): PasetoToken {
        // TODO expand service-test-vectors for v4 with implicit assertions
        if (implicitAssertion.isNotEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        val (encoded, footer) = paseto.verify(
            token = token,
            publicKey = keyProvider().publicKey,
            footer = json.encodeFooter(footer),
            implicitAssertion = implicitAssertion,
        )
        var decoded = json.decodeFromString(PasetoTokenSerializer, encoded)
        json.decodeFooter(footerValidation, footer).let { footer -> decoded = decoded.copy(footer = footer) }

        rules.verifyAll(decoded, Rule.Mode.DECODE)
        return decoded
    }

    override fun insecureGetFooter(token: String): TaintedPasetoFooter? =
        json.decodeFooter(footerValidation, extractFooter(token)).taint()
}

private fun Json.encodeFooter(footer: PasetoFooter): String = when (footer) {
    is ClaimFooter -> encodeToString(ClaimFooterSerializer, footer)
    is StringFooter -> footer.value
}

internal fun Json.decodeFooter(footerValidation: FooterValidation, footer: String): PasetoFooter {
    footerValidation(footer)

    return try {
        decodeFromString(ClaimFooterSerializer, footer)
    } catch (_: Exception) {
        StringFooter(footer)
    }
}
