package net.aholbrook.paseto

import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

private val json = Json { explicitNulls = false }

class SerdeTests {
    @ParameterizedTest
    @ValueSource(strings = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"])
    fun serialize_builtinClaimsAreNotOverridden(claim: String) {
        val token = token {
            issuedAt = null
            expiresAt = null
            claims {
                put(claim, "incorrect")
            }
        }

        val actual = json.encodeToString(PasetoTokenSerializer, token)
        actual shouldBe "{}"
    }

    @Test
    fun deserialize_builtinClaimsAreNotAddedToCustomClaims() {
        val token = json.decodeFromString(PasetoTokenSerializer, "{\"iss\":\"test\"}")
        token.issuer shouldBe "test"
        token.claims["iat"].shouldBeNull()
    }

    @Test
    fun serialize_boolean() {
        val token = token {
            issuedAt = null
            expiresAt = null
            claims {
                put("v", true)
            }
        }

        val actual = json.encodeToString(PasetoTokenSerializer, token)
        actual shouldBe "{\"v\":true}"
    }

    @Test
    fun deserialize_boolean() {
        val token = json.decodeFromString(PasetoTokenSerializer, "{\"v\":true}")
        token.claims["v"]?.booleanOrNull shouldBe true
    }

    @Test
    fun serialize_int() {
        val token = token {
            issuedAt = null
            expiresAt = null
            claims {
                put("v", Int.MIN_VALUE)
            }
        }

        val actual = json.encodeToString(PasetoTokenSerializer, token)
        actual shouldBe "{\"v\":${Int.MIN_VALUE}}"
    }

    @Test
    fun deserialize_int() {
        val token = json.decodeFromString(PasetoTokenSerializer, "{\"v\":${Int.MIN_VALUE}}")
        token.claims["v"]?.intOrNull shouldBe Int.MIN_VALUE
    }

    @Test
    fun serialize_long() {
        val token = token {
            issuedAt = null
            expiresAt = null
            claims {
                put("v", Long.MAX_VALUE)
            }
        }

        val actual = json.encodeToString(PasetoTokenSerializer, token)
        actual shouldBe "{\"v\":${Long.MAX_VALUE}}"
    }

    @Test
    fun deserialize_long() {
        val token = json.decodeFromString(PasetoTokenSerializer, "{\"v\":${Long.MAX_VALUE}}")
        token.claims["v"]?.longOrNull shouldBe Long.MAX_VALUE
    }

    @Test
    fun serialize_double() {
        val token = token {
            issuedAt = null
            expiresAt = null
            claims {
                put("v", 100.0)
            }
        }

        val actual = json.encodeToString(PasetoTokenSerializer, token)
        actual shouldBe "{\"v\":100.0}"
    }

    @Test
    fun deserialize_double() {
        val token = json.decodeFromString(PasetoTokenSerializer, "{\"v\":100.0}")
        token.claims["v"]?.doubleOrNull shouldBe 100.0
    }

    @Test
    fun serialize_double2() {
        val token = token {
            issuedAt = null
            expiresAt = null
            claims {
                put("v", 100.0123)
            }
        }

        val actual = json.encodeToString(PasetoTokenSerializer, token)
        actual shouldBe "{\"v\":100.0123}"
    }

    @Test
    fun deserialize_double2() {
        val token = json.decodeFromString(PasetoTokenSerializer, "{\"v\":100.0123}")
        token.claims["v"]?.doubleOrNull shouldBe 100.0123
    }

    @Test
    fun serialize_string() {
        val token = token {
            issuedAt = null
            expiresAt = null
            claims {
                put("v", "100")
            }
        }

        val actual = json.encodeToString(PasetoTokenSerializer, token)
        actual shouldBe "{\"v\":\"100\"}"
    }

    @Test
    fun deserialize_string() {
        val token = json.decodeFromString(PasetoTokenSerializer, "{\"v\":\"100\"}")
        token.claims["v"]?.stringOrNull shouldBe "100"
    }

    @Test
    fun serialize_null() {
        val token = token {
            issuedAt = null
            expiresAt = null
            claims {
                put("v", null)
            }
        }

        val actual = json.encodeToString(PasetoTokenSerializer, token)
        actual shouldBe "{\"v\":null}"
    }

    @Test
    fun deserialize_null() {
        val token = json.decodeFromString(PasetoTokenSerializer, "{\"v\":null}")
        token.claims["v"] shouldBe ClaimNull
    }

    @Test
    fun serialize_nestedClaimObject() {
        val token = token {
            issuedAt = null
            expiresAt = null
            claims {
                put(
                    "more",
                    claimObject {
                        put("nested", true)
                    },
                )
            }
        }

        val actual = json.encodeToString(PasetoTokenSerializer, token)
        actual shouldBe "{\"more\":{\"nested\":true}}"
    }

    @Test
    fun deserialize_nestedClaimObject() {
        val token = json.decodeFromString(PasetoTokenSerializer, "{\"more\":{\"nested\":true}}")
        token.claims["more"]?.objectOrNull?.get("nested")?.booleanOrNull shouldBe true
    }

    @Test
    fun serialize_claimArray() {
        val token = token {
            issuedAt = null
            expiresAt = null
            claims {
                put(
                    "v",
                    claimArray {
                        add(claimObject { put("x", true) })
                        add(claimArray { add(1) })
                        add(false)
                        add(1)
                        add(1.1)
                        add("1.3")
                        add(null)
                    },
                )
            }
        }

        val actual = json.encodeToString(PasetoTokenSerializer, token)
        actual shouldBe "{\"v\":[{\"x\":true},[1],false,1,1.1,\"1.3\",null]}"
    }

    @Test
    fun deserialize_claimArray() {
        val token = json.decodeFromString(
            PasetoTokenSerializer,
            "{\"v\":[{\"x\":true},[1],false,1,1.1,\"1.3\",null]}",
        )
        val array = token.claims["v"]?.arrayOrNull
        array?.get(0)?.objectOrNull?.get("x")?.booleanOrNull shouldBe true
        array?.get(1)?.arrayOrNull?.get(0)?.intOrNull shouldBe 1
        array?.get(2)?.booleanOrNull shouldBe false
        array?.get(3)?.intOrNull shouldBe 1
        array?.get(4)?.doubleOrNull shouldBe 1.1
        array?.get(5)?.stringOrNull shouldBe "1.3"
        array?.get(6) shouldBe ClaimNull
    }

    @Test
    fun claimNull_toJson() {
        ClaimNull.toJson() shouldBe JsonNull
    }

    @Test
    fun claimPrimitive_toStringMatchesJsonPrimitiveToString() {
        val claims = claimObject {
            put("str", "string")
            put("bool", true)
            put("int", 1)
            put("long", 2L)
            put("double", 3.14f)
        }

        claims["str"].toString() shouldBe JsonPrimitive("string").toString()
        claims["bool"]?.toString() shouldBe JsonPrimitive(true).toString()
        claims["int"]?.toString() shouldBe JsonPrimitive(1).toString()
        claims["long"]?.toString() shouldBe JsonPrimitive(2L).toString()
        claims["double"]?.toString() shouldBe JsonPrimitive(3.14).toString()
    }
}
