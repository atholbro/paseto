package net.aholbrook.paseto

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

private val RFC3339_FORMATTER = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC)

internal object PasetoTokenSerializer : KSerializer<PasetoToken> {
    private val reserved = setOf("iss", "sub", "aud", "exp", "nbf", "iat", "jti")

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("PasetoToken")

    override fun deserialize(decoder: Decoder): PasetoToken {
        val obj = (decoder as JsonDecoder).decodeJsonElement().jsonObject

        fun take(name: String) = obj[name]?.jsonPrimitive?.contentOrNull

        fun takeInstant(name: String): Instant? = obj[name]?.jsonPrimitive?.contentOrNull?.let { Instant.parse(it) }

        val claims = buildJsonObject {
            obj.filterNot { it.key in reserved }.forEach { put(it.key, it.value) }
        }

        return PasetoToken(
            issuer = take("iss"),
            subject = take("sub"),
            audience = take("aud"),
            expiresAt = takeInstant("exp"),
            notBefore = takeInstant("nbf"),
            issuedAt = takeInstant("iat"),
            tokenId = take("jti"),
            claims = claims.toClaim() as ClaimObject,
            footer = StringFooter(""),
        )
    }

    override fun serialize(encoder: Encoder, value: PasetoToken) {
        val output = encoder as JsonEncoder

        val obj = buildJsonObject {
            value.issuer?.let { put("iss", JsonPrimitive(it)) }
            value.subject?.let { put("sub", JsonPrimitive(it)) }
            value.audience?.let { put("aud", JsonPrimitive(it)) }
            value.expiresAt?.let {
                put("exp", JsonPrimitive(RFC3339_FORMATTER.format(it)))
            }
            value.notBefore?.let {
                put("nbf", JsonPrimitive(RFC3339_FORMATTER.format(it)))
            }
            value.issuedAt?.let {
                put("iat", JsonPrimitive(RFC3339_FORMATTER.format(it)))
            }
            value.tokenId?.let { put("jti", JsonPrimitive(it)) }

            (value.claims.toJson() as JsonObject)
                .filterNot { it.key in reserved }
                .forEach { (k, v) -> put(k, v) }
        }

        output.encodeJsonElement(obj)
    }
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
