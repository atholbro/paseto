package net.aholbrook.paseto

import kotlinx.serialization.json.JsonObject
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

/**
 * High-level JSON token model used by [TokenService].
 *
 * Standard claims are exposed as first-class properties and custom claims are stored in [claims].
 *
 * @property issuer Issuer claim (`iss`).
 * @property subject Subject claim (`sub`).
 * @property audience Audience claim (`aud`).
 * @property expiresAt Expiration time (`exp`).
 * @property notBefore Not-before time (`nbf`).
 * @property issuedAt Issued-at time (`iat`).
 * @property tokenId Token identifier (`jti`).
 * @property claims Custom claim object.
 * @property footer Token footer.
 */
@ConsistentCopyVisibility
data class Token internal constructor(
    val issuer: String?, // iss
    val subject: String?, // sub
    val audience: String?, // aud
    val expiresAt: Instant?, // exp
    val notBefore: Instant?, // nbf
    val issuedAt: Instant?, // iat
    val tokenId: String?, // jti
    val claims: ClaimObject,
    val footer: Footer,
)

/**
 * DSL builder for creating [Token] instances.
 *
 * @note Time values are truncated to second precision upon construction.
 */
@PasetoDslMarker
class TokenBuilder @PublishedApi internal constructor(clock: Clock) {
    /** Issuer claim (`iss`) identifying the token issuer. */
    var issuer: String? = null

    /** Subject claim (`sub`) identifying the principal the token represents. */
    var subject: String? = null

    /** Audience claim (`aud`) identifying the intended recipient of the token. */
    var audience: String? = null

    /**
     * Expiration time (`exp`).
     *
     * Defaults to **1 hour after token creation**.
     */
    var expiresAt: Instant? = clock.instant().plusSeconds(3600)

    /**
     * Not-before time (`nbf`) indicating when the token becomes valid.
     */
    var notBefore: Instant? = null

    /**
     * Issued-at time (`iat`).
     *
     * Defaults to the current time.
     */
    var issuedAt: Instant? = clock.instant()

    /** Token identifier (`jti`) used for uniqueness or revocation tracking. */
    var tokenId: String? = null

    /** Custom claims included in the token payload. */
    private var claims: ClaimObject = ClaimObject()

    /** Footer attached to the token. */
    private var footer: Footer = StringFooter("")

    /**
     * Replace custom claims using the claim-object DSL.
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
     * Replace custom claims with an existing [ClaimObject].
     *
     * @param claims Claim object to assign.
     */
    fun claims(claims: ClaimObject) {
        this.claims = claims
    }

    /**
     * Set footer directly using an existing footer value.
     *
     * @param footer Footer value to assign.
     */
    fun footer(footer: Footer) {
        this.footer = footer
    }

    /**
     * Set a plain string footer.
     *
     * @param footer Footer text.
     */
    fun footer(footer: String) {
        this.footer = StringFooter(footer)
    }

    /**
     * Build and set a structured claim footer.
     *
     * @param init Footer builder block.
     */
    @OptIn(ExperimentalContracts::class)
    fun footer(init: ClaimFooterBuilder.() -> Unit) {
        contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
        footer = ClaimFooterBuilder().apply(init).build()
    }

    @PublishedApi
    internal fun build(): Token = Token(
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

/**
 * Build a [Token] using DSL defaults and overrides from [init].
 *
 * @param clock Clock used for default `iat`/`exp` values.
 * @param init Token builder block.
 * @return Built [Token].
 */
@OptIn(ExperimentalContracts::class)
inline fun token(clock: Clock = Clock.systemUTC(), init: TokenBuilder.() -> Unit): Token {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
    return TokenBuilder(clock).apply(init).build()
}

/**
 * Escape hatch for direct access to the token's claims as a [JsonObject].
 *
 * This is an internal API because it couples the caller to the `kotlinx.serialization` JSON implementation.
 * It may change or be removed without notice if the underlying serialization strategy changes.
 * @receiver [Token].
 * @return Claims as a [JsonObject].
 */
@InternalApi
fun Token.claimsJson(): JsonObject = claims.toJson() as JsonObject
