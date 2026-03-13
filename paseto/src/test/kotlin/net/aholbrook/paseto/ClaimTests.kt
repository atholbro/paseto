package net.aholbrook.paseto

import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test

class ClaimTests {
    @Test
    fun claimElement_nullProperties() {
        val claim = ClaimNull
        claim.objectOrNull shouldBe null
        claim.arrayOrNull shouldBe null
        claim.primitiveOrNull shouldBe null
        claim.stringOrNull shouldBe null
        claim.booleanOrNull shouldBe null
        claim.intOrNull shouldBe null
        claim.longOrNull shouldBe null
        claim.doubleOrNull shouldBe null
    }

    @Test
    fun claimElement_nullAsType() {
        val claim = ClaimNull
        claim.asType<String>() shouldBe null
        claim.asType<Boolean>() shouldBe null
        claim.asType<Int>() shouldBe null
        claim.asType<Long>() shouldBe null
        claim.asType<Double>() shouldBe null
        claim.asType<ClaimObject>() shouldBe null
        claim.asType<ClaimArray>() shouldBe null
        claim.asType<ClaimTests>() shouldBe null
    }

    @Test
    fun claimElement_objectNullProperties() {
        val claim = ClaimObject()

        claim.primitiveOrNull shouldBe null
        claim.stringOrNull shouldBe null
        claim.booleanOrNull shouldBe null
        claim.intOrNull shouldBe null
        claim.longOrNull shouldBe null
        claim.doubleOrNull shouldBe null
    }

    @Test
    fun claimElement_stringOrNull() {
        val claim = claimObject {
            put("v", "str")
            put("null", null)
        }
        claim["v"]?.stringOrNull shouldBe "str"
        claim["null"]?.booleanOrNull shouldBe null
    }

    @Test
    fun claimElement_booleanOrNull() {
        val claim = claimObject {
            put("v", true)
            put("null", null)
        }
        claim["v"]?.booleanOrNull shouldBe true
        claim["null"]?.booleanOrNull shouldBe null
    }

    @Test
    fun claimElement_intOrNull() {
        val claim = claimObject {
            put("v", Int.MIN_VALUE)
            put("null", null)
        }
        claim["v"]?.intOrNull shouldBe Int.MIN_VALUE
        claim["null"]?.intOrNull shouldBe null
    }

    @Test
    fun claimElement_longOrNull() {
        val claim = claimObject {
            put("v", Long.MAX_VALUE)
            put("null", null)
        }
        claim["v"]?.longOrNull shouldBe Long.MAX_VALUE
        claim["null"]?.longOrNull shouldBe null
    }

    @Test
    fun claimElement_doubleOrNull() {
        val claim = claimObject {
            put("v", 1.5)
            put("null", null)
        }
        claim["v"]?.doubleOrNull shouldBe 1.5
        claim["null"]?.doubleOrNull shouldBe null
    }

    @Test
    fun claimElement_getAsTypeNull() {
        val claim = claimObject { put("v", null) }
        claim["v"]?.asType<String>().shouldBeNull()
        claim["v"]?.asType<Boolean>().shouldBeNull()
        claim["v"]?.asType<Int>().shouldBeNull()
        claim["v"]?.asType<Long>().shouldBeNull()
        claim["v"]?.asType<Double>().shouldBeNull()
        claim["v"]?.asType<ClaimObject>().shouldBeNull()
        claim["v"]?.asType<ClaimArray>().shouldBeNull()
        claim["v"]?.asType<ClaimTests>().shouldBeNull()
    }

    @Test
    fun claimElement_getAsTypeString() {
        val claim = claimObject { put("v", "test") }
        claim["v"]?.asType<String>() shouldBe "test"
    }

    @Test
    fun claimElement_getAsTypeBoolean() {
        val claim = claimObject { put("v", true) }
        claim["v"]?.asType<Boolean>() shouldBe true
    }

    @Test
    fun claimElement_getAsTypeInt() {
        val claim = claimObject { put("v", 1) }
        claim["v"]?.asType<Int>() shouldBe 1
    }

    @Test
    fun claimElement_getAsTypeLong() {
        val claim = claimObject { put("v", Long.MAX_VALUE) }
        claim["v"]?.asType<Long>() shouldBe Long.MAX_VALUE
    }

    @Test
    fun claimElement_getAsTypeDouble() {
        val claim = claimObject { put("v", 1.5) }
        claim["v"]?.asType<Double>() shouldBe 1.5
    }

    @Test
    fun claimElement_getAsTypeClaimObject() {
        val nested = claimObject { put("x", 1) }
        val claim = claimObject { put("v", nested) }
        claim["v"]?.asType<ClaimObject>() shouldBe nested
    }

    @Test
    fun claimElement_getAsTypeClaimArray() {
        val nested = claimArray {
            add(1)
            add("two")
        }
        val claim = claimObject { put("v", nested) }
        claim["v"]?.asType<ClaimArray>() shouldBe nested
    }

    @Test
    fun claimPrimitive_nonStringAsString() {
        val claim = claimObject {
            put("v", true)
        }

        claim["v"]?.stringOrNull shouldBe null
    }
}
