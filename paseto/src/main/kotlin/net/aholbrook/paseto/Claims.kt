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

inline fun <reified T> ClaimElement.asType(): T? = when(T::class) {
    String::class -> primitiveOrNull?.stringOrNull as? T
    Boolean::class -> primitiveOrNull?.booleanOrNull as? T
    Int::class -> primitiveOrNull?.intOrNull as? T
    Long::class -> primitiveOrNull?.longOrNull as? T
    Double::class -> primitiveOrNull?.doubleOrNull as? T
    ClaimObject::class -> objectOrNull as? T
    ClaimArray::class -> arrayOrNull as? T
    else -> null
}

object ClaimNull : ClaimElement

@JvmInline
@Suppress("JavaDefaultMethodsNotOverriddenByDelegation")
value class ClaimArray internal constructor(private val content: List<ClaimElement>) :
    ClaimElement, List<ClaimElement> by content {

    internal constructor(jsonArray: JsonArray) : this(jsonArray.map { it.toClaim() })
}

@JvmInline
value class ClaimObject internal constructor(private val content: Map<String, ClaimElement>) :
    ClaimElement, Map<String, ClaimElement> by content {

    internal constructor() : this(emptyMap())
    internal constructor(jsonObject: JsonObject) : this(
        content = jsonObject.mapValues { it.value.toClaim() }
    )
}

@JvmInline
value class ClaimPrimitive internal constructor(internal val primitive: JsonPrimitive) : ClaimElement {
    override val stringOrNull: String? get() = primitive.contentOrNull?.takeIf { primitive.isString }
    override val booleanOrNull: Boolean? get() = primitive.booleanOrNull
    override val intOrNull: Int? get() = primitive.intOrNull
    override val longOrNull: Long? get() = primitive.longOrNull
    override val doubleOrNull: Double? get() = primitive.doubleOrNull
    override fun toString(): String = primitive.toString()
}

class ClaimObjectBuilder @PublishedApi internal constructor() {
    private val content: MutableMap<String, ClaimElement> = linkedMapOf()

    fun put(key: String, value: ClaimElement): ClaimElement? = content.put(key, value)
    fun put(key: String, value: Boolean): ClaimElement? = content.put(key, primitiveValue(value))
    fun put(key: String, value: Number): ClaimElement? = content.put(key, primitiveValue(value))
    fun put(key: String, value: String): ClaimElement? = content.put(key, primitiveValue(value))
    fun put(key: String, value: Nothing?): ClaimElement? = content.put(key, primitiveValue(value))

    @PublishedApi
    internal fun build(): ClaimObject = ClaimObject(content)
}

@OptIn(ExperimentalContracts::class)
inline fun claimObject(init: ClaimObjectBuilder.() -> Unit): ClaimObject {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }

    val builder = ClaimObjectBuilder()
    builder.init()
    return builder.build()
}

class ClaimArrayBuilder @PublishedApi internal constructor() {
    private val content: MutableList<ClaimElement> = mutableListOf()

    fun add(value: ClaimElement): Boolean = content.add(value)
    fun add(value: Boolean): Boolean = content.add(primitiveValue(value))
    fun add(value: Number): Boolean = content.add(primitiveValue(value))
    fun add(value: String): Boolean = content.add(primitiveValue(value))
    fun add(value: Nothing?): Boolean = content.add(primitiveValue(value))

    @PublishedApi
    internal fun build(): ClaimArray = ClaimArray(content)
}

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

fun primitiveValue(value: Boolean?): ClaimPrimitive = ClaimPrimitive(JsonPrimitive(value))
fun primitiveValue(value: Number?): ClaimPrimitive = ClaimPrimitive(JsonPrimitive(value))
fun primitiveValue(value: String?): ClaimPrimitive = ClaimPrimitive(JsonPrimitive(value))
fun primitiveValue(value: Nothing?): ClaimPrimitive = ClaimPrimitive(JsonPrimitive(value))
