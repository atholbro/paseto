package net.aholbrook.paseto

import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

class TokenTests {
    @Test
    fun token_issuer() {
        pasetoToken { issuer = "test-issuer" }.issuer shouldBe "test-issuer"
    }

    @Test
    fun token_subject() {
        pasetoToken { subject = "test-subject" }.subject shouldBe "test-subject"
    }

    @Test
    fun token_audience() {
        pasetoToken { audience = "test-audience" }.audience shouldBe "test-audience"
    }

    @Test
    fun token_expiration() {
        val time = Instant.parse("2018-01-01T17:23:44Z")
        pasetoToken { expiresAt = time }.expiresAt shouldBe time
    }

    @Test
    fun token_notBefore() {
        val time = Instant.parse("2018-01-01T17:23:44Z")
        pasetoToken { notBefore = time }.notBefore shouldBe time
    }

    @Test
    fun token_issuedAt() {
        val time = Instant.parse("2018-01-01T17:23:44Z")
        pasetoToken { issuedAt = time }.issuedAt shouldBe time
    }

    @Test
    fun token_tokenId() {
        pasetoToken { tokenId = "test-tokenId" }.tokenId shouldBe "test-tokenId"
    }

    @Test
    fun token_claims() {
        val token = pasetoToken {
            claims {
                put("test", "data")
            }
        }

        token.claims["test"]?.asType<String>() shouldBe "data"
        token.claims["test"]?.stringOrNull shouldBe "data"
    }

    @Test
    fun token_claims_jsonEscapeHatch() {
        val token = pasetoToken {
            claims {
                put("test", "data")
            }
        }

        token.claimsJson()["test"]?.jsonPrimitive?.contentOrNull shouldBe "data"
    }

    @Test
    fun token_stringFooter() {
        pasetoToken {
            footer("abc")
        }.footer shouldBe footer("abc")
    }

    @Test
    fun token_mapFooter() {
        val footer = pasetoToken {
            footer {
                claims {
                    put("key", 1)
                }
            }
        }.footer as ClaimFooter

        footer.claims["key"]?.intOrNull shouldBe 1
    }

    @Test
    fun `expiration is 1 hour by default`() {
        val clock = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)
        val token = pasetoToken(clock) {}

        token.issuedAt shouldBe clock.instant()
        Duration.between(token.issuedAt, token.expiresAt) shouldBe Duration.ofHours(1)
    }
}
