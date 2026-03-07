package net.aholbrook.paseto

import kotlinx.serialization.json.JsonObject
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

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
    val footer: PasetoFooter,
)

@PasetoDslMarker
class TokenBuilder @PublishedApi internal constructor(clock: Clock) {
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
 */
@InternalApi
fun Token.claimsJson(): JsonObject = claims.toJson() as JsonObject
