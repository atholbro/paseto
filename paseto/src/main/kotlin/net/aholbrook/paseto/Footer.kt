package net.aholbrook.paseto

import kotlinx.serialization.json.JsonObject
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

sealed interface PasetoFooter

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
    is ClaimFooter -> TaintedClaimFooter(keyId, wrappedKey, claims)
    is StringFooter -> TaintedStringFooter(value)
}

/**
 * Escape hatch for direct access to the footer's claims as a [JsonObject].
 *
 * This is an internal API because it couples the caller to the `kotlinx.serialization` JSON implementation.
 * It may change or be removed without notice if the underlying serialization strategy changes.
 */
@InternalApi
fun ClaimFooter.claimsJson(): JsonObject = claims.toJson() as JsonObject

/**
 * Escape hatch for direct access to the footer's claims as a [JsonObject].
 *
 * This is an internal API because it couples the caller to the `kotlinx.serialization` JSON implementation.
 * It may change or be removed without notice if the underlying serialization strategy changes.
 */
@InternalApi
fun TaintedClaimFooter.claimsJson(): JsonObject = claims.toJson() as JsonObject
