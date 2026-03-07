package net.aholbrook.paseto.protocol

import net.aholbrook.paseto.UrlSafeNoPadding
import net.aholbrook.paseto.crypto.ECDSA_P384_PUBLICKEYBYTES
import net.aholbrook.paseto.crypto.ECDSA_P384_SECRETKEYBYTES
import net.aholbrook.paseto.crypto.ED25519_PUBLICKEYBYTES
import net.aholbrook.paseto.crypto.ED25519_SECRETKEYBYTES
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.decodeOrNull
import net.aholbrook.paseto.exception.GenericInvalidFooterException
import net.aholbrook.paseto.exception.InvalidFooterException
import net.aholbrook.paseto.exception.InvalidHeaderException
import net.aholbrook.paseto.exception.PasetoParseException
import kotlin.io.encoding.Base64

internal const val SEPARATOR: String = "."

enum class Version {
    V1,
    V2,
    V3,
    V4,
    ;

    internal val paseto: Paseto get() = when (this) {
        V1 -> PasetoV1
        V2 -> PasetoV2
        V3 -> PasetoV3
        V4 -> PasetoV4
    }

    internal val asymmetricPublicKeySize: Int get() = when (this) {
        V1 -> -1
        V2 -> ED25519_PUBLICKEYBYTES
        V3 -> ECDSA_P384_PUBLICKEYBYTES
        V4 -> ED25519_PUBLICKEYBYTES
    }
    internal val asymmetricSecretKeySize: Int get() = when (this) {
        V1 -> -1
        V2 -> ED25519_SECRETKEYBYTES
        V3 -> ECDSA_P384_SECRETKEYBYTES
        V4 -> ED25519_SECRETKEYBYTES
    }
    internal val symmetricKeySize: Int = 32
}

internal enum class Purpose {
    LOCAL,
    PUBLIC,
}

internal sealed interface Paseto {
    val version: Version
    val supportsImplicitAssertion: Boolean

    fun encrypt(m: ByteArray, key: SymmetricKey, footer: String = "", implicitAssertion: String = ""): String

    fun decrypt(
        token: String,
        key: SymmetricKey,
        footer: String = "",
        implicitAssertion: String = "",
    ): Pair<String, String>

    fun sign(m: ByteArray, secretKey: AsymmetricSecretKey, footer: String = "", implicitAssertion: String = ""): String

    fun verify(
        token: String,
        publicKey: AsymmetricPublicKey,
        footer: String = "",
        implicitAssertion: String = "",
    ): Pair<String, String>
}

internal fun extractFooter(token: String): String {
    val footer = split(token).footer
    if (footer.isNotEmpty()) {
        return Base64.UrlSafeNoPadding.decodeOrNull(footer)?.toString(Charsets.UTF_8)
            ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)
    }

    return ""
}

internal data class PasetoSections(val version: String, val purpose: String, val payload: String, val footer: String)

/**
 * Splits a Paseto token into its 4 sections: VERSION, PURPOSE, PAYLOAD, FOOTER.
 *
 * If the token does not contain a footer, then the 4th string in the array will be null. If the string does
 * not contain either 3 or 4 sections separated by a period (ASCII 2E) then a null array will be returned as the
 * token cannot be valid.
 *
 * @param token Paseto token.
 * @return PasetoSections or null if token is missing required sections.
 */
@Suppress("MagicNumber")
internal fun split(token: String): PasetoSections {
    if (token.isNotEmpty()) {
        val tokens = token.split(SEPARATOR)

        if (tokens.size == 4) {
            return PasetoSections(tokens[0], tokens[1], tokens[2], tokens[3])
        } else if (tokens.size == 3) {
            return PasetoSections(tokens[0], tokens[1], tokens[2], "")
        }
    }

    throw PasetoParseException(PasetoParseException.Reason.MISSING_SECTIONS, token)
}

internal fun decodeFooter(token: String, sections: PasetoSections, expectedFooter: String): String {
    val userFooter = sections.footer
    val decodedFooter = Base64.UrlSafeNoPadding.decodeOrNull(userFooter)
        ?.toString(Charsets.UTF_8)
        ?: throw PasetoParseException(PasetoParseException.Reason.INVALID_BASE64, token)

    if (!decodedFooter.constantTimeEquals(expectedFooter)) {
        throw GenericInvalidFooterException(decodedFooter, expectedFooter)
    }

    return decodedFooter
}
