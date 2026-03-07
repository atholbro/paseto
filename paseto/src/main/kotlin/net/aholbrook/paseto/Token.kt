package net.aholbrook.paseto

import kotlinx.serialization.json.JsonObject
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

@ConsistentCopyVisibility
data class PasetoToken internal constructor(
    val issuer: String?, // iss
    val subject: String?, // sub
    val audience: String?, // aud
    val expiresAt: Instant?, // exp
    val notBefore: Instant?, // nbf
    val issuedAt: Instant?, // iat
    val tokenId: String?, // jti
    val claims: ClaimObject,
    val footer: PasetoFooter,
)

@PasetoDslMarker
class PasetoTokenBuilder @PublishedApi internal constructor(clock: Clock) {
    var issuer: String? = null // iss
    var subject: String? = null // sub
    var audience: String? = null // aud
    var expiresAt: Instant? = clock.instant().plusSeconds(3600) // exp
    var notBefore: Instant? = null // nbf
    var issuedAt: Instant? = clock.instant() // iat
    var tokenId: String? = null // jti
    private var claims: ClaimObject = ClaimObject()
    private var footer: PasetoFooter = StringFooter("")

    @OptIn(ExperimentalContracts::class)
    fun claims(init: ClaimObjectBuilder.() -> Unit) {
        contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }

        val builder = ClaimObjectBuilder()
        builder.init()
        claims = builder.build()
    }

    fun claims(claims: ClaimObject) {
        this.claims = claims
    }

    fun footer(footer: PasetoFooter) {
        this.footer = footer
    }

    fun footer(footer: String) {
        this.footer = StringFooter(footer)
    }

    @OptIn(ExperimentalContracts::class)
    fun footer(init: ClaimFooterBuilder.() -> Unit) {
        contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
        footer = ClaimFooterBuilder().apply(init).build()
    }

    @PublishedApi
    internal fun build(): PasetoToken = PasetoToken(
        issuer = issuer,
        subject = subject,
        audience = audience,
        expiresAt = expiresAt?.truncatedTo(ChronoUnit.SECONDS),
        notBefore = notBefore?.truncatedTo(ChronoUnit.SECONDS),
        issuedAt = issuedAt?.truncatedTo(ChronoUnit.SECONDS),
        tokenId = tokenId,
        claims = claims,
        footer = footer,
    )
}

@OptIn(ExperimentalContracts::class)
inline fun pasetoToken(clock: Clock = Clock.systemUTC(), init: PasetoTokenBuilder.() -> Unit): PasetoToken {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
    return PasetoTokenBuilder(clock).apply(init).build()
}

sealed interface PasetoFooter

object EmptyFooter : PasetoFooter

@JvmInline
value class StringFooter internal constructor(val value: String) : PasetoFooter

@ConsistentCopyVisibility
data class ClaimFooter internal constructor(
    val keyId: String?, // kid
    val wrappedKey: String?, // wpk
    val claims: ClaimObject,
) : PasetoFooter

@PasetoDslMarker
class ClaimFooterBuilder @PublishedApi internal constructor() {
    var keyId: String? = null // kid
    var wrappedKey: String? = null // wpk
    private var claims: ClaimObject = ClaimObject()

    @OptIn(ExperimentalContracts::class)
    fun claims(init: ClaimObjectBuilder.() -> Unit) {
        contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }

        val builder = ClaimObjectBuilder()
        builder.init()
        claims = builder.build()
    }

    fun claims(claims: ClaimObject) {
        this.claims = claims
    }

    @PublishedApi
    internal fun build(): ClaimFooter = ClaimFooter(
        keyId = keyId,
        wrappedKey = wrappedKey,
        claims = claims,
    )
}

fun footer(footer: String) = StringFooter(footer)

@OptIn(ExperimentalContracts::class)
inline fun footer(init: ClaimFooterBuilder.() -> Unit): ClaimFooter {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
    return ClaimFooterBuilder().apply(init).build()
}

/**
 * A Paseto footer extracted from a token which has not been cryptographically verified. It is therefore possible that
 * a [TaintedPasetoFooter] has been tampered with.
 *
 * This is useful when the footer is used to carry information required to verify the key, like a key id (kid) claim.
 */
sealed interface TaintedPasetoFooter

object TaintedEmptyFooter : TaintedPasetoFooter

@JvmInline
value class TaintedStringFooter(val value: String) : TaintedPasetoFooter

@ConsistentCopyVisibility
data class TaintedClaimFooter internal constructor(
    val keyId: String?, // kid
    val wrappedKey: String?, // wpk
    val claims: ClaimObject,
) : TaintedPasetoFooter

/**
 * Converts a [PasetoFooter] to it's [TaintedPasetoFooter] variant.
 *
 * This can be used to compare an [TaintedClaimFooter] against a [ClaimFooter] built using the [footer] builder.
 * @receiver A [PasetoFooter] instance to turn taint.
 * @return A [TaintedPasetoFooter] representation of the given [PasetoFooter].
 */
fun PasetoFooter.taint(): TaintedPasetoFooter? = when (this) {
    is EmptyFooter -> TaintedEmptyFooter
    is ClaimFooter -> TaintedClaimFooter(keyId, wrappedKey, claims)
    is StringFooter -> TaintedStringFooter(value)
}

/**
 * Escape hatch for direct access to the token's claims as a [JsonObject].
 *
 * This is an internal API because it couples the caller to the `kotlinx.serialization` JSON implementation.
 * It may change or be removed without notice if the underlying serialization strategy changes.
 */

@InternalApi
fun PasetoToken.claimsJson(): JsonObject = claims.toJson() as JsonObject
