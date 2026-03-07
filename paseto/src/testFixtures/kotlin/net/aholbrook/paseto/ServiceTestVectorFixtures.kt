package net.aholbrook.paseto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.time.Instant
import kotlin.collections.forEach

@Serializable
data class ServiceTestVectors(val name: String, val version: String, val tests: List<ServiceTestVector>)

@Serializable
data class ServiceTestVector(
    val name: String,
    val mode: String,
    val nonce: String? = null,
    val key: String? = null,
    @SerialName("public-key")
    val publicKey: String? = null,
    @SerialName("secret-key")
    val secretKey: String? = null,
    val payload: JsonObject,
    val footer: JsonElement? = null,
    val token: String,
)

fun tokenFromVector(vector: ServiceTestVector): PasetoToken {
    val tokenReserved = setOf("iss", "sub", "aud", "exp", "nbf", "iat", "jti")
    val footerReserved = setOf("kid", "wpk")

    return pasetoToken {
        issuer = vector.payload["iss"]?.jsonPrimitive?.contentOrNull
        subject = vector.payload["sub"]?.jsonPrimitive?.contentOrNull
        audience = vector.payload["aud"]?.jsonPrimitive?.contentOrNull
        expiresAt = vector.payload["exp"]?.jsonPrimitive?.contentOrNull?.let { Instant.parse(it) }
        notBefore = vector.payload["nbf"]?.jsonPrimitive?.contentOrNull?.let { Instant.parse(it) }
        issuedAt = vector.payload["iat"]?.jsonPrimitive?.contentOrNull?.let { Instant.parse(it) }
        tokenId = vector.payload["jti"]?.jsonPrimitive?.contentOrNull
        claims(
            JsonObject(vector.payload.filterNot { it.key in tokenReserved })
                .toClaimElement() as ClaimObject,
        )

        when (val f = vector.footer) {
            null, is JsonNull -> footer("")

            is JsonPrimitive -> footer(f.content)

            is JsonObject -> footer {
                keyId = f["kid"]?.jsonPrimitive?.contentOrNull
                wrappedKey = f["wpk"]?.jsonPrimitive?.contentOrNull
                claims(JsonObject(f.filterNot { it.key in footerReserved }).toClaimElement() as ClaimObject)
            }

            else -> footer("")
        }
    }
}

fun JsonElement.toClaimElement(): ClaimElement = when (this) {
    is JsonNull -> ClaimNull

    is JsonPrimitive -> {
        when {
            this.isString -> primitiveValue(this.contentOrNull)
            this.booleanOrNull != null -> primitiveValue(this.booleanOrNull)
            this.intOrNull != null -> primitiveValue(this.intOrNull)
            this.longOrNull != null -> primitiveValue(this.longOrNull)
            this.doubleOrNull != null -> primitiveValue(this.doubleOrNull)
            else -> ClaimNull
        }
    }

    is JsonArray -> claimArray {
        forEach { add(it.toClaimElement()) }
    }

    is JsonObject -> claimObject {
        forEach { (key, element) ->
            put(key, element.toClaimElement())
        }
    }
}
