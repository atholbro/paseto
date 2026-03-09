package net.aholbrook.paseto

import kotlinx.serialization.json.JsonObject
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

/**
 * Marker interface for supported token footer types.
 */
sealed interface Footer

/**
 * String footer value.
 *
 * @property value Footer text.
 */
@JvmInline
value class StringFooter internal constructor(val value: String) : Footer

/**
 * Structured footer with reserved `kid`/`wpk` fields plus arbitrary custom claims.
 *
 * @property keyId Optional key identifier (`kid`).
 * @property wrappedKey Optional wrapped key value (`wpk`).
 * @property claims Custom footer claims.
 */
@ConsistentCopyVisibility
data class ClaimFooter internal constructor(
    val keyId: String?, // kid
    val wrappedKey: String?, // wpk
    val claims: ClaimObject,
) : Footer

/**
 * DSL builder for [ClaimFooter].
 *
 * @property keyId Optional key identifier (`kid`).
 * @property wrappedKey Optional wrapped key value (`wpk`).
 */
@PasetoDslMarker
class ClaimFooterBuilder @PublishedApi internal constructor() {
    var keyId: String? = null // kid
    var wrappedKey: String? = null // wpk
    private var claims: ClaimObject = ClaimObject()

    /**
     * Replace footer custom claims using the claim-object DSL.
     *
     * @param init Claim-object builder block.
     */
    @OptIn(ExperimentalContracts::class)
    fun claims(init: ClaimObjectBuilder.() -> Unit) {
        contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }

        val builder = ClaimObjectBuilder()
        builder.init()
        claims = builder.build()
    }

    /**
     * Replace footer custom claims with an existing [ClaimObject].
     *
     * @param claims Claim object to store on the footer.
     */
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

/**
 * Create a plain [StringFooter].
 *
 * @param footer Footer text.
 * @return A [StringFooter] value.
 */
fun footer(footer: String) = StringFooter(footer)

/**
 * Build a structured [ClaimFooter] using the footer DSL.
 *
 * @param init Footer builder block.
 * @return A [ClaimFooter] value.
 */
@OptIn(ExperimentalContracts::class)
inline fun footer(init: ClaimFooterBuilder.() -> Unit): ClaimFooter {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
    return ClaimFooterBuilder().apply(init).build()
}

/**
 * A Paseto footer extracted from a token which has not been cryptographically verified. It is therefore possible that
 * a [TaintedFooter] has been tampered with.
 *
 * This is useful when the footer is used to carry information required to verify the key, like a key id (kid) claim.
 */
sealed interface TaintedFooter

/**
 * Tainted string footer extracted without token verification.
 *
 * @property value Unverified footer text.
 */
@JvmInline
value class TaintedStringFooter(val value: String) : TaintedFooter

/**
 * Tainted claim footer extracted without token verification.
 *
 * @property keyId Optional unverified key identifier (`kid`).
 * @property wrappedKey Optional unverified wrapped key value (`wpk`).
 * @property claims Unverified footer claims.
 */
@ConsistentCopyVisibility
data class TaintedClaimFooter internal constructor(
    val keyId: String?, // kid
    val wrappedKey: String?, // wpk
    val claims: ClaimObject,
) : TaintedFooter

/**
 * Converts a [Footer] to its [TaintedFooter] variant.
 *
 * This can be used to compare an [TaintedClaimFooter] against a [ClaimFooter] built using the [footer] builder.
 * @receiver A [Footer] instance to turn taint.
 * @return A [TaintedFooter] representation of the given [Footer].
 */
fun Footer.taint(): TaintedFooter = when (this) {
    is ClaimFooter -> TaintedClaimFooter(keyId, wrappedKey, claims)
    is StringFooter -> TaintedStringFooter(value)
}

/**
 * Escape hatch for direct access to footer claims as a [JsonObject].
 *
 * This is an internal API because it couples the caller to the `kotlinx.serialization` JSON implementation.
 * It may change or be removed without notice if the underlying serialization strategy changes.
 * @receiver Verified [ClaimFooter].
 * @return Footer claims as a [JsonObject].
 */
@InternalApi
fun ClaimFooter.claimsJson(): JsonObject = claims.toJson() as JsonObject

/**
 * Escape hatch for direct access to footer claims as a [JsonObject].
 *
 * This is an internal API because it couples the caller to the `kotlinx.serialization` JSON implementation.
 * It may change or be removed without notice if the underlying serialization strategy changes.
 * @receiver Unverified [TaintedClaimFooter].
 * @return Footer claims as a [JsonObject].
 */
@InternalApi
fun TaintedClaimFooter.claimsJson(): JsonObject = claims.toJson() as JsonObject
