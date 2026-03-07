package net.aholbrook.paseto

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.aholbrook.paseto.exception.FooterExceedsMaxDepthException
import net.aholbrook.paseto.exception.FooterExceedsMaxKeysException
import net.aholbrook.paseto.exception.FooterExceedsMaxLengthException
import net.aholbrook.paseto.exception.FooterJsonParseException
import net.aholbrook.paseto.protocol.jsonCountDepthAndKeys

/**
 * Determines how token footer text is interpreted when decoding.
 *
 * - [AUTO]: Treat object-like footer text (`{...}`) as JSON claims when possible;
 *   otherwise fall back to a plain string footer.
 * - [CLAIMS]: Require a valid JSON claims footer and fail if parsing/validation fails.
 * - [STRING]: Always treat footer text as plain string data (no claims parsing).
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

internal fun Json.encodeFooter(footerOptions: FooterOptions, footer: PasetoFooter): String {
    val encoded = when (footer) {
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

internal object ClaimFooterSerializer : KSerializer<ClaimFooter> {
    private val reserved = setOf("kid", "wpk")

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ClaimFooter")

    override fun deserialize(decoder: Decoder): ClaimFooter {
        when (val element = (decoder as JsonDecoder).decodeJsonElement()) {
            is JsonObject -> {
                fun take(name: String) = element.jsonObject[name]?.jsonPrimitive?.contentOrNull

                val claims = buildJsonObject {
                    element.jsonObject.filterNot { it.key in reserved }.forEach { put(it.key, it.value) }
                }

                return ClaimFooter(
                    keyId = take("kid"),
                    wrappedKey = take("wpk"),
                    claims = claims.toClaim() as ClaimObject,
                )
            }

            else -> throw SerializationException("expected object, got $element")
        }
    }

    override fun serialize(encoder: Encoder, value: ClaimFooter) {
        val output = encoder as JsonEncoder
        val element = buildJsonObject {
            value.keyId?.let { put("kid", JsonPrimitive(it)) }
            value.wrappedKey?.let { put("wpk", JsonPrimitive(it)) }

            (value.claims.toJson() as JsonObject)
                .filterNot { it.key in reserved }
                .forEach { (k, v) -> put(k, v) }
        }
        output.encodeJsonElement(element)
    }
}
