package net.aholbrook.paseto.rules

import net.aholbrook.paseto.PasetoDslMarker
import net.aholbrook.paseto.Token
import net.aholbrook.paseto.exception.MultipleValidationErrorsException
import net.aholbrook.paseto.exception.RuleValidationException
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

/** Result type for rule execution. */
sealed interface RuleResult

/** Rule executed successfully. */
object RuleVerified : RuleResult

/**
 * Rule failed with a [RuleValidationException].
 *
 * @property cause Validation exception thrown by the rule.
 */
@JvmInline
value class RuleFailed(val cause: RuleValidationException) : RuleResult

/**
 * A validation rule applied to a token during encoding and/or decoding.
 */
sealed interface Rule {
    /**
     * Verify that the given token passes this rule.
     *
     * @param token Token to check.
     * @param mode Whether verification is running during encode or decode.
     * @param currentResults The results of all rules which have run before this rule.
     */
    operator fun invoke(token: Token, mode: Mode, currentResults: Map<Rule, RuleResult>)

    enum class Mode {
        ENCODE,
        DECODE,
    }
}

/** Interface for custom ad-hoc rules. */
fun interface CustomRule : Rule

/** Immutable rule set used by [net.aholbrook.paseto.TokenService]. */
class Rules internal constructor(@PublishedApi internal val rules: List<Rule>) {
    /**
     * Run all rules and return per-rule results.
     *
     * Throws [MultipleValidationErrorsException] if any rule fails.
     *
     * @param token Token to validate.
     * @param mode Encode/decode mode.
     * @return Rule results keyed by the executed [Rule].
     */
    fun verifyAll(token: Token, mode: Rule.Mode): Map<Rule, RuleResult> {
        val context = mutableMapOf<Rule, RuleResult>()
        val mre = MultipleValidationErrorsException(token)

        for (rule in rules) {
            try {
                rule(token, mode, context)
                context[rule] = RuleVerified
            } catch (re: RuleValidationException) {
                re.rule = rule
                mre.add(re)
                context[rule] = RuleFailed(re)
            }
        }

        if (mre.exceptions.isNotEmpty()) {
            throw mre
        }
        return context
    }

    /**
     * Find the first configured rule by exact runtime type.
     *
     * @return Rule instance or `null` if not found.
     */
    inline fun <reified T> findByTypeOrNull(): T? = rules.find { it::class == T::class } as? T
}

/**
 * Find a result entry by exact rule type.
 *
 * @receiver Rule-result map returned by [Rules.verifyAll].
 * @return Matching rule/result pair or `null` if not found.
 */
inline fun <reified T> Map<Rule, RuleResult>.findByTypeOrNull(): Pair<Rule, RuleResult>? =
    entries.find { it.key::class == T::class }?.let { it.key to it.value }

/**
 * Builder DSL for configuring a set of [Rule]s used during token validation.
 *
 * By default, [issuedInPast] and [notExpired] are enabled.
 */
@PasetoDslMarker
class RulesBuilder @PublishedApi internal constructor() {
    /** Require the token audience (`aud`) to match the provided value. */
    var forAudience: ForAudience? = null

    /** Require the token identifier (`jti`) to match the provided value. */
    var identifiedBy: IdentifiedBy? = null

    /** Require the token issuer (`iss`) to match the provided value. */
    var issuedBy: IssuedBy? = null

    /**
     * Ensures the token was issued in the past (`iat` ≤ now).
     *
     * Enabled by default.
     */
    var issuedInPast: IssuedInPast? = IssuedInPast()

    /** Ensures the token cannot be used before its not-before time (`nbf`). */
    var notBefore: NotBefore? = null

    /**
     * Ensures the token has not expired (`exp` ≥ now).
     *
     * Enabled by default.
     */
    var notExpired: NotExpired? = NotExpired()

    /** Require the token subject (`sub`) to match the provided value. */
    var subject: Subject? = null

    /**
     * Validates the token against the current time using all temporal claims
     * (`iat`, `nbf`, and `exp`).
     */
    var validAt: ValidAt? = null

    /** Additional user-defined validation rules. */
    val customRules = mutableListOf<CustomRule>()

    @PublishedApi
    internal fun build(): Rules = Rules(
        listOfNotNull(
            forAudience,
            identifiedBy,
            issuedBy,
            issuedInPast,
            notBefore,
            notExpired,
            subject,
            validAt,
        ) + customRules,
    )

    @PublishedApi
    internal fun copy(rules: Rules) {
        forAudience = rules.findByTypeOrNull()
        identifiedBy = rules.findByTypeOrNull()
        issuedBy = rules.findByTypeOrNull()
        issuedInPast = rules.findByTypeOrNull()
        notBefore = rules.findByTypeOrNull<NotBefore>()
        notExpired = rules.findByTypeOrNull()
        subject = rules.findByTypeOrNull()
        validAt = rules.findByTypeOrNull()
        customRules.addAll(rules.rules.mapNotNull { it as? CustomRule })
    }
}

/**
 * Build a [Rules] instance using the rules DSL.
 *
 * @param init Rule-builder block.
 * @return Built [Rules].
 */
@OptIn(ExperimentalContracts::class)
inline fun rules(init: RulesBuilder.() -> Unit = { }): Rules {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
    return RulesBuilder().apply(init).build()
}

/**
 * Copy an existing [Rules] and mutate it with [init].
 *
 * @param copyFrom Existing rule set to copy.
 * @param init Rule mutations to apply.
 * @return Built [Rules].
 */
@OptIn(ExperimentalContracts::class)
inline fun rules(copyFrom: Rules, init: RulesBuilder.() -> Unit): Rules {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
    return RulesBuilder().apply { copy(copyFrom) }.apply(init).build()
}
