package net.aholbrook.paseto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

/**
 * Marker type for custom claim values.
 *
 * Claims can be represented as objects, arrays, primitives, or null.
 *
 * @property objectOrNull Value as [ClaimObject] when object-typed.
 * @property arrayOrNull Value as [ClaimArray] when array-typed.
 * @property primitiveOrNull Value as [ClaimPrimitive] when primitive-typed.
 * @property stringOrNull Primitive string value if present.
 * @property booleanOrNull Primitive boolean value if present.
 * @property intOrNull Primitive int value if present.
 * @property longOrNull Primitive long value if present.
 * @property doubleOrNull Primitive double value if present.
 */
sealed interface ClaimElement {
    val objectOrNull: ClaimObject? get() = this as? ClaimObject
    val arrayOrNull: ClaimArray? get() = this as? ClaimArray
    val primitiveOrNull: ClaimPrimitive? get() = this as? ClaimPrimitive

    val stringOrNull: String? get() = null
    val booleanOrNull: Boolean? get() = null
    val intOrNull: Int? get() = null
    val longOrNull: Long? get() = null
    val doubleOrNull: Double? get() = null
}

/**
 * Attempt to read this claim as a supported Kotlin type.
 *
 * Supported types are: [String], [Boolean], [Int], [Long], [Double], [ClaimObject],
 * and [ClaimArray]. Calling with an unsupported type will return `null`.
 *
 * @receiver Claim element to cast.
 * @return Cast value or `null` if unsupported/unmatched.
 */
inline fun <reified T> ClaimElement.asType(): T? = when (T::class) {
    String::class -> primitiveOrNull?.stringOrNull as? T
    Boolean::class -> primitiveOrNull?.booleanOrNull as? T
    Int::class -> primitiveOrNull?.intOrNull as? T
    Long::class -> primitiveOrNull?.longOrNull as? T
    Double::class -> primitiveOrNull?.doubleOrNull as? T
    ClaimObject::class -> objectOrNull as? T
    ClaimArray::class -> arrayOrNull as? T
    else -> null
}

/** Null claim value. */
object ClaimNull : ClaimElement

/** Array claim value. */
@JvmInline
@Suppress("JavaDefaultMethodsNotOverriddenByDelegation")
value class ClaimArray internal constructor(private val content: List<ClaimElement>) :
    ClaimElement,
    List<ClaimElement> by content {

    internal constructor(jsonArray: JsonArray) : this(jsonArray.map { it.toClaim() })
}

/** Object claim value. */
@JvmInline
value class ClaimObject internal constructor(private val content: Map<String, ClaimElement>) :
    ClaimElement,
    Map<String, ClaimElement> by content {

    internal constructor() : this(emptyMap())
    internal constructor(jsonObject: JsonObject) : this(
        content = jsonObject.mapValues { it.value.toClaim() },
    )
}

/** Primitive claim value. */
@JvmInline
value class ClaimPrimitive internal constructor(internal val primitive: JsonPrimitive) : ClaimElement {
    override val stringOrNull: String? get() = primitive.contentOrNull?.takeIf { primitive.isString }
    override val booleanOrNull: Boolean? get() = primitive.booleanOrNull
    override val intOrNull: Int? get() = primitive.intOrNull
    override val longOrNull: Long? get() = primitive.longOrNull
    override val doubleOrNull: Double? get() = primitive.doubleOrNull
    override fun toString(): String = primitive.toString()
}

/** DSL Builder for [ClaimObject]. */
@PasetoDslMarker
class ClaimObjectBuilder @PublishedApi internal constructor() {
    private val content: MutableMap<String, ClaimElement> = linkedMapOf()

    /**
     * Put a nested claim value.
     *
     * @param key Claim key.
     * @param value Claim value.
     * @return Previous value for [key], if present.
     */
    fun put(key: String, value: ClaimElement): ClaimElement? = content.put(key, value)

    /**
     * Put a boolean claim value.
     *
     * @param key Claim key.
     * @param value Claim value.
     * @return Previous value for [key], if present.
     */
    fun put(key: String, value: Boolean): ClaimElement? = content.put(key, primitiveValue(value))

    /**
     * Put a numeric claim value.
     *
     * @param key Claim key.
     * @param value Claim value.
     * @return Previous value for [key], if present.
     */
    fun put(key: String, value: Number): ClaimElement? = content.put(key, primitiveValue(value))

    /**
     * Put a string claim value.
     *
     * @param key Claim key.
     * @param value Claim value.
     * @return Previous value for [key], if present.
     */
    fun put(key: String, value: String): ClaimElement? = content.put(key, primitiveValue(value))

    /**
     * Put a `null` claim value.
     *
     * @param key Claim key.
     * @param value Claim value.
     * @return Previous value for [key], if present.
     */
    fun put(key: String, value: Nothing?): ClaimElement? = content.put(key, primitiveValue(value))

    @PublishedApi
    internal fun build(): ClaimObject = ClaimObject(content)
}

/**
 * Build a [ClaimObject] using the claim DSL.
 *
 * @param init Claim-object builder block.
 * @return Built [ClaimObject].
 */
@OptIn(ExperimentalContracts::class)
inline fun claimObject(init: ClaimObjectBuilder.() -> Unit): ClaimObject {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }

    val builder = ClaimObjectBuilder()
    builder.init()
    return builder.build()
}

/** DSL builder for [ClaimArray]. */
@PasetoDslMarker
class ClaimArrayBuilder @PublishedApi internal constructor() {
    private val content: MutableList<ClaimElement> = mutableListOf()

    /**
     * Add a nested claim value.
     *
     * @param value Claim value to append.
     * @return `true` when appended.
     */
    fun add(value: ClaimElement): Boolean = content.add(value)

    /**
     * Add a boolean value.
     *
     * @param value Claim value to append.
     * @return `true` when appended.
     */
    fun add(value: Boolean): Boolean = content.add(primitiveValue(value))

    /**
     * Add a numeric value.
     *
     * @param value Claim value to append.
     * @return `true` when appended.
     */
    fun add(value: Number): Boolean = content.add(primitiveValue(value))

    /**
     * Add a string value.
     *
     * @param value Claim value to append.
     * @return `true` when appended.
     */
    fun add(value: String): Boolean = content.add(primitiveValue(value))

    /**
     * Add a `null` value.
     *
     * @param value Claim value to append.
     * @return `true` when appended.
     */
    fun add(value: Nothing?): Boolean = content.add(primitiveValue(value))

    @PublishedApi
    internal fun build(): ClaimArray = ClaimArray(content)
}

/**
 * Build a [ClaimArray] using the claim DSL.
 *
 * @param init Array builder block.
 * @return Built [ClaimArray].
 */
@OptIn(ExperimentalContracts::class)
inline fun claimArray(init: ClaimArrayBuilder.() -> Unit): ClaimArray {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }

    val builder = ClaimArrayBuilder()
    builder.init()
    return builder.build()
}

internal fun JsonElement.toClaim(): ClaimElement = when (this) {
    is JsonNull -> ClaimNull
    is JsonPrimitive -> ClaimPrimitive(this)
    is JsonObject -> ClaimObject(this)
    is JsonArray -> ClaimArray(this)
}

internal fun ClaimElement.toJson(): JsonElement = when (this) {
    is ClaimNull -> JsonNull
    is ClaimPrimitive -> primitive
    is ClaimArray -> JsonArray(this.map { it.toJson() })
    is ClaimObject -> JsonObject(this.mapValues { it.value.toJson() })
}

/**
 * Convert a nullable boolean into a [ClaimPrimitive].
 *
 * @param value Boolean value.
 * @return Primitive claim.
 */
fun primitiveValue(value: Boolean?): ClaimPrimitive = ClaimPrimitive(JsonPrimitive(value))

/**
 * Convert a nullable number into a [ClaimPrimitive].
 *
 * @param value Number value.
 * @return Primitive claim.
 */
fun primitiveValue(value: Number?): ClaimPrimitive = ClaimPrimitive(JsonPrimitive(value))

/**
 * Convert a nullable string into a [ClaimPrimitive].
 *
 * @param value String value.
 * @return Primitive claim.
 */
fun primitiveValue(value: String?): ClaimPrimitive = ClaimPrimitive(JsonPrimitive(value))

/**
 * Convert nullable `Nothing` into a JSON null [ClaimPrimitive].
 *
 * @param value Null literal.
 * @return Primitive claim.
 */
fun primitiveValue(value: Nothing?): ClaimPrimitive = ClaimPrimitive(JsonPrimitive(value))
