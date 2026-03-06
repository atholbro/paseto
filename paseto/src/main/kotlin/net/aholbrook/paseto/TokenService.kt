@file:Suppress("DuplicatedCode")

package net.aholbrook.paseto

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import net.aholbrook.paseto.exception.CannotSignWithoutSecretKey
import net.aholbrook.paseto.exception.ImplicitAssertionsNotSupportedException
import net.aholbrook.paseto.protocol.KeyPair
import net.aholbrook.paseto.protocol.Paseto
import net.aholbrook.paseto.protocol.SymmetricKey
import net.aholbrook.paseto.protocol.Version
import net.aholbrook.paseto.protocol.extractFooter
import net.aholbrook.paseto.rules.Rule
import net.aholbrook.paseto.rules.Rules
import net.aholbrook.paseto.rules.rules
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

sealed interface Purpose {
    class Public(val keyProvider: () -> KeyPair) : Purpose
    class Local(val keyProvider: () -> SymmetricKey) : Purpose
}

@PasetoDslMarker
class TokenServiceBuilder @PublishedApi internal constructor() {
    var rules: Rules = rules()

    @PublishedApi
    internal fun build(version: Version, purpose: Purpose): TokenService = purpose.let { purpose ->
        when (purpose) {
            is Purpose.Public -> {
                PublicTokenService(
                    paseto = version.paseto,
                    keyProvider = purpose.keyProvider,
                    rules = rules,
                )
            }

            is Purpose.Local -> {
                LocalTokenService(
                    paseto = version.paseto,
                    keyProvider = purpose.keyProvider,
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
    fun encode(token: PasetoToken, implicitAssertion: String? = null): String
    fun decode(token: String, footer: PasetoFooter? = null, implicitAssertion: String? = null): PasetoToken

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
    private val json: Json = Json { explicitNulls = false },
) : TokenService {
    override fun encode(token: PasetoToken, implicitAssertion: String?): String {
        if (!implicitAssertion.isNullOrEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        rules.verifyAll(token, Rule.Mode.ENCODE)
        val encoded = json.encodeToString(PasetoTokenSerializer, token)
        val encodedFooter = json.encodeFooter(token.footer)
        return paseto.encrypt(encoded, keyProvider(), encodedFooter, implicitAssertion)
    }

    override fun decode(token: String, footer: PasetoFooter?, implicitAssertion: String?): PasetoToken {
        if (!implicitAssertion.isNullOrEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        val encoded = paseto.decrypt(token, keyProvider(), json.encodeFooter(footer), implicitAssertion)
        var decoded = json.decodeFromString(PasetoTokenSerializer, encoded)
        json.decodeFooter(extractFooter(token))?.let { footer -> decoded = decoded.copy(footer = footer) }

        rules.verifyAll(decoded, Rule.Mode.DECODE)
        return decoded
    }

    override fun insecureGetFooter(token: String): TaintedPasetoFooter? =
        json.decodeFooter(extractFooter(token)).taint()
}

internal class PublicTokenService internal constructor(
    private val paseto: Paseto,
    private val keyProvider: () -> KeyPair,
    private val rules: Rules,
    private val json: Json = Json { explicitNulls = false },
) : TokenService {
    override fun encode(token: PasetoToken, implicitAssertion: String?): String {
        // TODO expand service-test-vectors for v4 with implicit assertions
        if (!implicitAssertion.isNullOrEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        rules.verifyAll(token, Rule.Mode.ENCODE)
        val encoded = json.encodeToString(PasetoTokenSerializer, token)
        val encodedFooter = json.encodeFooter(token.footer)
        val keyPair = keyProvider()
        if (keyPair.secretKey == null) {
            throw CannotSignWithoutSecretKey()
        }
        return paseto.sign(encoded, keyPair.secretKey, encodedFooter, implicitAssertion)
    }

    override fun decode(token: String, footer: PasetoFooter?, implicitAssertion: String?): PasetoToken {
        // TODO expand service-test-vectors for v4 with implicit assertions
        if (!implicitAssertion.isNullOrEmpty() && !paseto.supportsImplicitAssertion) {
            throw ImplicitAssertionsNotSupportedException(paseto.version)
        }

        val encoded = paseto.verify(token, keyProvider().publicKey, json.encodeFooter(footer), implicitAssertion)
        var decoded = json.decodeFromString(PasetoTokenSerializer, encoded)
        json.decodeFooter(extractFooter(token))?.let { footer -> decoded = decoded.copy(footer = footer) }

        rules.verifyAll(decoded, Rule.Mode.DECODE)
        return decoded
    }

    override fun insecureGetFooter(token: String): TaintedPasetoFooter? =
        json.decodeFooter(extractFooter(token)).taint()
}

private fun Json.encodeFooter(footer: PasetoFooter?): String? = footer?.let { footer ->
    when (footer) {
        is ClaimFooter -> encodeToString(ClaimFooterSerializer, footer)
        is StringFooter -> footer.value
    }
}

internal fun Json.decodeFooter(footer: String?): PasetoFooter? = footer?.let { footer ->
    try {
        decodeFromString(ClaimFooterSerializer, footer)
    } catch (_: SerializationException) {
        StringFooter(footer)
    } catch (_: IllegalArgumentException) {
        StringFooter(footer)
    }
}
